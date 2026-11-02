package vaultbackend

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestCustodyRoutesRequireSudoAndRejectUnknownFields(t *testing.T) {
	backend := New(nil)
	require.NoError(t, backend.Setup(t.Context(), logical.TestBackendConfig()))
	require.Equal(t, []string{"v1/custody/*"}, backend.SpecialPaths().Root)
	for _, action := range []string{"prepare", "export", "import", "activate", "abort", "status"} {
		for _, suffix := range []string{"", "/"} {
			req := logical.TestRequest(t, logical.UpdateOperation, "v1/custody/"+action+suffix)
			req.Storage = new(logical.InmemStorage)
			req.Data = map[string]any{"unknown_secret_field": "sentinel-must-not-appear"}
			_, err := backend.HandleRequest(t.Context(), req)
			require.ErrorContains(t, err, "invalid custody request")
			require.NotContains(t, err.Error(), "sentinel-must-not-appear")
		}
	}
}
func TestCustodyTransportReturnsOnlyPublicReceiverMetadata(t *testing.T) {
	backend := New(nil)
	require.NoError(t, backend.Setup(t.Context(), logical.TestBackendConfig()))
	storage := new(logical.InmemStorage)
	req := logical.TestRequest(t, logical.UpdateOperation, "v1/custody/prepare")
	req.Storage = storage
	req.Data = map[string]any{"transfer_id": "transport-1", "checkpoint": strings.Repeat("a", 64), "key_ids": []string{"a"}}
	first, err := backend.HandleRequest(t.Context(), req)
	require.NoError(t, err)
	raw, err := json.Marshal(first.Data)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "AGE-SECRET-KEY")
	require.NotContains(t, string(raw), "private")
	require.Equal(t, "prepared", first.Data["phase"])
	second, err := backend.HandleRequest(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, first.Data, second.Data)
	req.Data["checkpoint"] = strings.Repeat("b", 64)
	_, err = backend.HandleRequest(t.Context(), req)
	require.Error(t, err)
}
