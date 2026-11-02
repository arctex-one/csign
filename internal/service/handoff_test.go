package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/lazysteff/csign/v2/internal/faults"
	"github.com/lazysteff/csign/v2/internal/repository"
	"github.com/lazysteff/csign/v2/internal/signingops"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func handoffRepo(storage logical.Storage) *repository.VaultKeyRepository {
	return repository.NewVaultKeyRepository(storage, signingops.Default())
}
func handoffKey(t *testing.T, storage logical.Storage, id string, legacy, active bool) []byte {
	t.Helper()
	key, err := NewKeyService(handoffRepo(storage), signingops.Default(), func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC) }).Create(t.Context(), v1.CreateKeyRequest{KeyID: id, ChainFamily: v1.ChainFamilyTRON, CustodyMode: v1.CustodyModeMVP, Labels: map[string]string{"purpose": "custody"}, Policy: v1.Policy{AllowedNetworks: []string{"tron-mainnet"}}})
	require.NoError(t, err)
	key.Active = active
	if legacy {
		key.RecordVersion = 0
		key.KeyType = ""
		key.MaterialFormat = ""
	}
	raw, err := json.Marshal(key)
	require.NoError(t, err)
	require.NoError(t, storage.Put(t.Context(), &logical.StorageEntry{Key: "keys/" + id, Value: raw}))
	return raw
}
func handoffSelection() v1.CustodySelection {
	return v1.CustodySelection{TransferID: "custody-1", Checkpoint: strings.Repeat("a", 64), KeyIDs: []string{"tenant/a", "tenant/b"}}
}
func handoffExport(t *testing.T, source, target logical.Storage) (*HandoffService, v1.CustodyImportRequest) {
	t.Helper()
	receiver := NewHandoffService(handoffRepo(target))
	prepared, err := receiver.Prepare(t.Context(), handoffSelection())
	require.NoError(t, err)
	exported, err := NewHandoffService(handoffRepo(source)).Export(t.Context(), v1.CustodyExportRequest{Selection: handoffSelection(), Recipient: prepared.Recipient})
	require.NoError(t, err)
	return receiver, v1.CustodyImportRequest{TransferID: prepared.TransferID, Digest: exported.Digest, Ciphertext: exported.Ciphertext}
}
func TestHandoffPreservesSelectedCustodyAndRequiresActivation(t *testing.T) {
	source, target := new(logical.InmemStorage), new(logical.InmemStorage)
	originalA := handoffKey(t, source, "tenant/a", true, true)
	originalB := handoffKey(t, source, "tenant/b", false, false)
	handoffKey(t, source, "unselected", false, true)
	unrelated := handoffKey(t, target, "existing", false, true)
	require.NoError(t, source.Put(t.Context(), &logical.StorageEntry{Key: "foreign/business-secret", Value: []byte("must-not-leave-source")}))
	receiver, req := handoffExport(t, source, target)
	require.False(t, bytes.Contains(req.Ciphertext, []byte("private_key_hex")))
	require.False(t, bytes.Contains(req.Ciphertext, []byte("must-not-leave-source")))
	state, err := handoffRepo(target).LoadImport(t.Context(), req.TransferID)
	require.NoError(t, err)
	require.NotEmpty(t, state.Recipient.Private)
	result, err := receiver.Import(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, "staged", result.Phase)
	for id, raw := range map[string][]byte{"tenant/a": originalA, "tenant/b": originalB, "existing": unrelated} {
		stored, err := target.Get(t.Context(), "keys/"+id)
		require.NoError(t, err)
		require.Equal(t, raw, stored.Value)
		key, err := handoffRepo(target).GetKey(t.Context(), id)
		require.NoError(t, err)
		require.Equal(t, id == "existing", key.Active)
	}
	ids, err := handoffRepo(target).ListKeyIDs(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"existing", "tenant/a", "tenant/b"}, ids)
	foreign, err := target.Get(t.Context(), "foreign/business-secret")
	require.NoError(t, err)
	require.Nil(t, foreign)
	for id, raw := range map[string][]byte{"tenant/a": originalA, "tenant/b": originalB} {
		stored, err := source.Get(t.Context(), "keys/"+id)
		require.NoError(t, err)
		require.Equal(t, raw, stored.Value)
	}
	key, err := handoffRepo(target).GetKey(t.Context(), "tenant/a")
	require.NoError(t, err)
	key.Active = true
	require.Equal(t, faults.Conflict, faults.KindOf(handoffRepo(target).PutKey(t.Context(), *key)))
	_, err = NewKeyService(handoffRepo(target), signingops.Default(), time.Now).SetActive(t.Context(), "tenant/a", true)
	require.Error(t, err)
	replay, err := receiver.Import(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, result, replay)
	state, err = handoffRepo(target).LoadImport(t.Context(), req.TransferID)
	require.NoError(t, err)
	require.Empty(t, state.Recipient.Private)
	activation := v1.CustodyActivation{TransferID: req.TransferID, Digest: req.Digest}
	_, err = receiver.Activate(t.Context(), activation)
	require.Error(t, err)
	activation.Fence = strings.Repeat("b", 64)
	result, err = receiver.Activate(t.Context(), activation)
	require.NoError(t, err)
	require.Equal(t, "active", result.Phase)
	for id, want := range map[string]bool{"tenant/a": true, "tenant/b": false, "existing": true} {
		key, err := handoffRepo(target).GetKey(t.Context(), id)
		require.NoError(t, err)
		require.Equal(t, want, key.Active)
	}
	_, err = receiver.Activate(t.Context(), activation)
	require.NoError(t, err)
	_, err = receiver.Abort(t.Context(), v1.CustodyReference{TransferID: req.TransferID})
	require.Error(t, err)
	// A legitimate update after activation must survive an import replay.
	_, err = NewKeyService(handoffRepo(target), signingops.Default(), time.Now).SetActive(t.Context(), "tenant/a", false)
	require.NoError(t, err)
	_, err = receiver.Import(t.Context(), req)
	require.NoError(t, err)
	key, err = handoffRepo(target).GetKey(t.Context(), "tenant/a")
	require.NoError(t, err)
	require.False(t, key.Active)
}

type interruptedStorage struct {
	logical.Storage
	fail   int
	writes int
}

func (s *interruptedStorage) Put(ctx context.Context, e *logical.StorageEntry) error {
	s.writes++
	if s.fail > 0 && s.writes == s.fail {
		return errors.New("injected storage failure")
	}
	return s.Storage.Put(ctx, e)
}
func (s *interruptedStorage) Delete(ctx context.Context, key string) error {
	s.writes++
	if s.fail > 0 && s.writes == s.fail {
		return errors.New("injected storage failure")
	}
	return s.Storage.Delete(ctx, key)
}
func TestHandoffEveryInterruptedWriteResumesWithoutEnablingKeys(t *testing.T) {
	// Import: journal, 2*(marker,key), final stage. Activation: one journal write.
	for fail := 1; fail <= 7; fail++ {
		t.Run(strconv.Itoa(fail), func(t *testing.T) {
			source := new(logical.InmemStorage)
			target := &interruptedStorage{Storage: new(logical.InmemStorage)}
			handoffKey(t, source, "tenant/a", false, true)
			handoffKey(t, source, "tenant/b", true, true)
			receiver, req := handoffExport(t, source, target)
			target.writes = 0
			target.fail = fail
			_, err := receiver.Import(t.Context(), req)
			if fail <= 6 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			for _, id := range handoffSelection().KeyIDs {
				key, err := handoffRepo(target).GetKey(t.Context(), id)
				if err == nil {
					require.False(t, key.Active)
				} else {
					require.ErrorIs(t, err, repository.ErrKeyNotFound)
				}
			}
			// Reconstruct the service over persisted state, simulating plugin restart.
			target.fail = 0
			receiver = NewHandoffService(handoffRepo(target))
			result, err := receiver.Import(t.Context(), req)
			require.NoError(t, err)
			require.Equal(t, "staged", result.Phase)
			target.writes = 0
			target.fail = 1
			_, err = receiver.Activate(t.Context(), v1.CustodyActivation{TransferID: req.TransferID, Digest: req.Digest, Fence: strings.Repeat("c", 64)})
			require.Error(t, err)
			for _, id := range handoffSelection().KeyIDs {
				key, err := handoffRepo(target).GetKey(t.Context(), id)
				require.NoError(t, err)
				require.False(t, key.Active)
			}
			target.fail = 0
			_, err = receiver.Activate(t.Context(), v1.CustodyActivation{TransferID: req.TransferID, Digest: req.Digest, Fence: strings.Repeat("c", 64)})
			require.NoError(t, err)
		})
	}
}
func TestHandoffAbortResumesAndPreservesExistingKeys(t *testing.T) {
	for fail := 1; fail <= 6; fail++ {
		t.Run(strconv.Itoa(fail), func(t *testing.T) {
			source := new(logical.InmemStorage)
			target := &interruptedStorage{Storage: new(logical.InmemStorage)}
			handoffKey(t, source, "tenant/a", false, true)
			handoffKey(t, source, "tenant/b", false, true)
			existing := handoffKey(t, target, "existing", false, true)
			receiver, req := handoffExport(t, source, target)
			_, err := receiver.Import(t.Context(), req)
			require.NoError(t, err)
			target.writes = 0
			target.fail = fail
			_, err = receiver.Abort(t.Context(), v1.CustodyReference{TransferID: req.TransferID})
			require.Error(t, err)
			target.fail = 0
			receiver = NewHandoffService(handoffRepo(target))
			result, err := receiver.Abort(t.Context(), v1.CustodyReference{TransferID: req.TransferID})
			require.NoError(t, err)
			require.Equal(t, "aborted", result.Phase)
			for _, id := range handoffSelection().KeyIDs {
				_, err := handoffRepo(target).GetKey(t.Context(), id)
				require.ErrorIs(t, err, repository.ErrKeyNotFound)
			}
			stored, err := target.Get(t.Context(), "keys/existing")
			require.NoError(t, err)
			require.Equal(t, existing, stored.Value)
			_, err = receiver.Import(t.Context(), req)
			require.Error(t, err)
		})
	}
}
func TestHandoffRejectsConflictsBeforeWritingAnyKeys(t *testing.T) {
	source, target := new(logical.InmemStorage), new(logical.InmemStorage)
	handoffKey(t, source, "tenant/a", false, true)
	handoffKey(t, source, "tenant/b", false, true)
	existing := handoffKey(t, target, "tenant/b", false, true)
	receiver, req := handoffExport(t, source, target)
	_, err := receiver.Import(t.Context(), req)
	require.Equal(t, faults.Conflict, faults.KindOf(err))
	key, err := target.Get(t.Context(), "keys/tenant/a")
	require.NoError(t, err)
	require.Nil(t, key)
	key, err = target.Get(t.Context(), "keys/tenant/b")
	require.NoError(t, err)
	require.Equal(t, existing, key.Value)
	status, err := receiver.Status(t.Context(), v1.CustodyReference{TransferID: req.TransferID})
	require.NoError(t, err)
	require.Equal(t, "prepared", status.Phase)
}
func TestHandoffRejectsInvalidEncryptedBundles(t *testing.T) {
	for _, mode := range []string{"tampered", "wrong-key", "wrong-recipient", "checkpoint", "selection", "version", "record", "digest", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			source, target := new(logical.InmemStorage), new(logical.InmemStorage)
			handoffKey(t, source, "tenant/a", false, true)
			handoffKey(t, source, "tenant/b", false, true)
			receiver, req := handoffExport(t, source, target)
			state, err := handoffRepo(target).LoadImport(t.Context(), req.TransferID)
			require.NoError(t, err)
			bundle, err := receiver.open(state, req)
			require.NoError(t, err)
			switch mode {
			case "tampered":
				req.Ciphertext[len(req.Ciphertext)-1] ^= 1
			case "digest":
				req.Digest = strings.Repeat("0", 64)
			default:
				switch mode {
				case "wrong-recipient":
					bundle.Recipient = "other"
				case "checkpoint":
					bundle.Selection.Checkpoint = strings.Repeat("d", 64)
				case "selection":
					bundle.Records = bundle.Records[:1]
				case "version":
					bundle.Version = 2
				case "record":
					bundle.Records[1].Raw = []byte(`{"id":"tenant/b"}`)
				}
				raw, err := json.Marshal(bundle)
				require.NoError(t, err)
				if mode == "trailing" {
					raw = append(raw, []byte(" {}")...)
				}
				recipient, err := age.ParseX25519Recipient(state.Recipient.Public)
				require.NoError(t, err)
				if mode == "wrong-key" {
					other, err := age.GenerateX25519Identity()
					require.NoError(t, err)
					recipient = other.Recipient()
				}
				var ciphertext bytes.Buffer
				writer, err := age.Encrypt(&ciphertext, recipient)
				require.NoError(t, err)
				_, err = writer.Write(raw)
				require.NoError(t, err)
				require.NoError(t, writer.Close())
				req.Ciphertext = ciphertext.Bytes()
				req.Digest = repository.RecordHash(raw)
			}
			_, err = receiver.Import(t.Context(), req)
			require.Error(t, err)
			ids, err := handoffRepo(target).ListKeyIDs(t.Context())
			require.NoError(t, err)
			require.Empty(t, ids)
		})
	}
}
func TestHandoffFailClosedOnLostGateAndChangedReadback(t *testing.T) {
	source, target := new(logical.InmemStorage), new(logical.InmemStorage)
	handoffKey(t, source, "tenant/a", false, true)
	handoffKey(t, source, "tenant/b", false, true)
	receiver, req := handoffExport(t, source, target)
	_, err := receiver.Import(t.Context(), req)
	require.NoError(t, err)
	record, err := target.Get(t.Context(), "keys/tenant/a")
	require.NoError(t, err)
	original := bytes.Clone(record.Value)
	record.Value = append(record.Value, ' ')
	require.NoError(t, target.Put(t.Context(), record))
	_, err = receiver.Activate(t.Context(), v1.CustodyActivation{TransferID: req.TransferID, Digest: req.Digest, Fence: strings.Repeat("e", 64)})
	require.Error(t, err)
	_, err = receiver.Abort(t.Context(), v1.CustodyReference{TransferID: req.TransferID})
	require.Error(t, err)
	record.Value = original
	require.NoError(t, target.Put(t.Context(), record))
	require.NoError(t, target.Delete(t.Context(), "custody-imports/receivers/"+req.TransferID))
	key, err := handoffRepo(target).GetKey(t.Context(), "tenant/a")
	require.NoError(t, err)
	require.False(t, key.Active)
	key.Active = true
	require.Error(t, handoffRepo(target).PutKey(t.Context(), *key))
}

func TestHandoffSelectionValidation(t *testing.T) {
	for _, mode := range []string{"empty", "traversal", "duplicate", "unsorted", "checkpoint", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			selection := handoffSelection()
			switch mode {
			case "empty":
				selection.KeyIDs = nil
			case "traversal":
				selection.TransferID = "../receiver"
			case "duplicate":
				selection.KeyIDs = []string{"a", "a"}
			case "unsorted":
				selection.KeyIDs = []string{"z", "a"}
			case "checkpoint":
				selection.Checkpoint = "checkpoint"
			case "oversized":
				selection.KeyIDs = make([]string, maxCustodyKeys+1)
			}
			_, err := NewHandoffService(handoffRepo(new(logical.InmemStorage))).Prepare(t.Context(), selection)
			require.Equal(t, faults.Invalid, faults.KindOf(err))
		})
	}
}
func TestHandoffEd25519RecordRemainsExact(t *testing.T) {
	source, target := new(logical.InmemStorage), new(logical.InmemStorage)
	key, err := NewKeyService(handoffRepo(source), signingops.Default(), time.Now).Create(t.Context(), v1.CreateKeyRequest{KeyID: "ed25519", KeyType: "ed25519", CustodyMode: v1.CustodyModeMVP})
	require.NoError(t, err)
	selection := v1.CustodySelection{TransferID: "ed25519", Checkpoint: strings.Repeat("f", 64), KeyIDs: []string{key.ID}}
	receiver := NewHandoffService(handoffRepo(target))
	prepared, err := receiver.Prepare(t.Context(), selection)
	require.NoError(t, err)
	exported, err := NewHandoffService(handoffRepo(source)).Export(t.Context(), v1.CustodyExportRequest{Selection: selection, Recipient: prepared.Recipient})
	require.NoError(t, err)
	_, err = receiver.Import(t.Context(), v1.CustodyImportRequest{TransferID: selection.TransferID, Ciphertext: exported.Ciphertext, Digest: exported.Digest})
	require.NoError(t, err)
	original, err := source.Get(t.Context(), "keys/ed25519")
	require.NoError(t, err)
	stored, err := target.Get(t.Context(), "keys/ed25519")
	require.NoError(t, err)
	require.Equal(t, original.Value, stored.Value)
}

func TestHandoffRejectsExternalCustody(t *testing.T) {
	source := new(logical.InmemStorage)
	handoffKey(t, source, "external", false, true)
	key, err := handoffRepo(source).GetKey(t.Context(), "external")
	require.NoError(t, err)
	key.CustodyMode = v1.CustodyModePKCS11
	key.ExternalSignerRef = "pkcs11:source-only"
	key.PrivateKeyHex = ""
	key.MaterialFormat = ""
	raw, err := json.Marshal(key)
	require.NoError(t, err)
	require.NoError(t, source.Put(t.Context(), &logical.StorageEntry{Key: "keys/external", Value: raw}))
	require.Equal(t, faults.Unsupported, faults.KindOf(handoffRepo(source).ValidateRecord("external", raw)))
	_, err = handoffRepo(source).ExportRecord(t.Context(), "external")
	require.Equal(t, faults.Unsupported, faults.KindOf(err))
}
