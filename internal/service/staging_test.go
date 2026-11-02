package service

import (
	"strings"
	"testing"

	"github.com/arctex-one/csign/v2/internal/repository"
	v1 "github.com/arctex-one/csign/v2/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestStagedHandoffNeverPublishesLiveKeysBeforeFence(t *testing.T) {
	source, target := new(logical.InmemStorage), new(logical.InmemStorage)
	handoffKey(t, source, "tenant/a", false, true)
	handoffKey(t, source, "tenant/b", true, true)
	receiver, req := handoffExport(t, source, target)
	_, err := receiver.Import(t.Context(), req)
	require.NoError(t, err)
	for _, id := range handoffSelection().KeyIDs {
		// Older signers know only keys/. A status update in an older signer must
		// never be able to expose the Source private key before a durable fence.
		live, err := target.Get(t.Context(), "keys/"+id)
		require.NoError(t, err)
		if live != nil {
			t.Fatal("Source key was published in live storage before the fence")
		}
		staged, err := handoffRepo(target).GetKey(t.Context(), id)
		require.NoError(t, err)
		require.False(t, staged.Active)
	}
	// The old format's normal key API has no Source material to enable or sign.
	liveIDs, err := target.List(t.Context(), "keys/")
	require.NoError(t, err)
	require.Empty(t, liveIDs)
}

func TestActivationEveryWriteRetainsFenceAndResumes(t *testing.T) {
	for fail := 1; fail <= 4; fail++ {
		t.Run(strings.Repeat("x", fail), func(t *testing.T) {
			source := new(logical.InmemStorage)
			target := &interruptedStorage{Storage: new(logical.InmemStorage)}
			originalA := handoffKey(t, source, "tenant/a", true, true)
			originalB := handoffKey(t, source, "tenant/b", false, false)
			receiver, req := handoffExport(t, source, target)
			_, err := receiver.Import(t.Context(), req)
			require.NoError(t, err)
			activation := v1.CustodyActivation{TransferID: req.TransferID, Digest: req.Digest, Fence: strings.Repeat("f", 64)}
			target.fail = fail
			target.writes = 0
			_, err = receiver.Activate(t.Context(), activation)
			require.Error(t, err)
			for _, id := range handoffSelection().KeyIDs {
				visible, err := handoffRepo(target).GetKey(t.Context(), id)
				require.NoError(t, err)
				require.False(t, visible.Active)
				live, err := target.Get(t.Context(), "keys/"+id)
				require.NoError(t, err)
				if live != nil {
					state, err := handoffRepo(target).LoadImport(t.Context(), req.TransferID)
					require.NoError(t, err)
					require.Equal(t, "activating", state.Phase)
					require.Equal(t, activation.Fence, state.Fence, "fence must precede every live key write")
				}
			}
			if fail > 1 {
				_, err = receiver.Abort(t.Context(), v1.CustodyReference{TransferID: req.TransferID})
				require.Error(t, err, "activation must recover forward after a possible live publication")
				changed := activation
				changed.Fence = strings.Repeat("e", 64)
				_, err = receiver.Activate(t.Context(), changed)
				require.Error(t, err)
			}
			target.fail = 0
			receiver = NewHandoffService(handoffRepo(target))
			result, err := receiver.Activate(t.Context(), activation)
			require.NoError(t, err)
			require.Equal(t, "active", result.Phase)
			for id, raw := range map[string][]byte{"tenant/a": originalA, "tenant/b": originalB} {
				live, err := target.Get(t.Context(), "keys/"+id)
				require.NoError(t, err)
				require.Equal(t, raw, live.Value)
			}
		})
	}
}
func TestStagedAbortPreservesForeignLiveKeyFromOlderSigner(t *testing.T) {
	source, target := new(logical.InmemStorage), new(logical.InmemStorage)
	handoffKey(t, source, "tenant/a", false, true)
	handoffKey(t, source, "tenant/b", false, true)
	receiver, req := handoffExport(t, source, target)
	_, err := receiver.Import(t.Context(), req)
	require.NoError(t, err)
	other := new(logical.InmemStorage)
	foreign := handoffKey(t, other, "tenant/a", false, true)
	require.NoError(t, target.Put(t.Context(), &logical.StorageEntry{Key: "keys/tenant/a", Value: foreign}))
	_, err = receiver.Activate(t.Context(), v1.CustodyActivation{TransferID: req.TransferID, Digest: req.Digest, Fence: strings.Repeat("a", 64)})
	require.Error(t, err)
	_, err = receiver.Abort(t.Context(), v1.CustodyReference{TransferID: req.TransferID})
	require.NoError(t, err)
	live, err := target.Get(t.Context(), "keys/tenant/a")
	require.NoError(t, err)
	require.Equal(t, foreign, live.Value)
	_, err = handoffRepo(target).GetKey(t.Context(), "tenant/b")
	require.ErrorIs(t, err, repository.ErrKeyNotFound)
}

func TestPreviousReceiversRequireExplicitStagingRecovery(t *testing.T) {
	for _, phase := range []string{"staged", "active"} {
		t.Run(phase, func(t *testing.T) {
			source, target := new(logical.InmemStorage), new(logical.InmemStorage)
			originalA := handoffKey(t, source, "tenant/a", true, true)
			originalB := handoffKey(t, source, "tenant/b", false, false)
			receiver, req := handoffExport(t, source, target)
			repo := handoffRepo(target)
			state, err := repo.LoadImport(t.Context(), req.TransferID)
			require.NoError(t, err)
			state.Format = 0
			state.Phase = phase
			state.Recipient.Private = ""
			state.Bundle = repository.BundleProof{Digest: req.Digest, Cipher: repository.RecordHash(req.Ciphertext)}
			for id, raw := range map[string][]byte{"tenant/a": originalA, "tenant/b": originalB} {
				require.NoError(t, target.Put(t.Context(), &logical.StorageEntry{Key: "keys/" + id, Value: raw}))
				marker, err := logical.StorageEntryJSON("custody-imports/keys/"+id, repository.ImportMarker{TransferID: req.TransferID})
				require.NoError(t, err)
				require.NoError(t, target.Put(t.Context(), marker))
				state.Records = append(state.Records, repository.RecordProof{ID: id, Hash: repository.RecordHash(raw)})
			}
			if phase == "active" {
				state.Fence = strings.Repeat("c", 64)
			}
			require.NoError(t, repo.SaveImport(t.Context(), state))
			key, err := repo.GetKey(t.Context(), "tenant/a")
			require.NoError(t, err)
			require.Equal(t, phase == "active", key.Active)
			activation := v1.CustodyActivation{TransferID: req.TransferID, Digest: req.Digest, Fence: strings.Repeat("c", 64)}
			_, err = receiver.Activate(t.Context(), activation)
			if phase == "active" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			_, err = receiver.Abort(t.Context(), v1.CustodyReference{TransferID: req.TransferID})
			require.NoError(t, err)
			for _, id := range handoffSelection().KeyIDs {
				_, err := repo.GetKey(t.Context(), id)
				require.ErrorIs(t, err, repository.ErrKeyNotFound)
			}
		})
	}
}
