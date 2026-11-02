package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/lazysteff/csign/v2/internal/domain"
	enc "github.com/lazysteff/csign/v2/internal/encoding"
	"github.com/lazysteff/csign/v2/internal/faults"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

const importPrefix = "custody-imports/"

// ImportFormat keeps pre-fence key material outside the live key namespace.
const ImportFormat = 2

var ErrImportNotFound = errors.New("custody receiver not found")
var errMarkerNotFound = errors.New("custody import marker not found")

// ImportState is stored only within this mount's encrypted Vault storage. Its
// wrapping identity is discarded after staging or abort, never returned by API.
type ImportState struct {
	Format    int                 `json:"format,omitempty"`
	Selection v1.CustodySelection `json:"selection"`
	Phase     string              `json:"phase"`
	Recipient WrappingIdentity    `json:"recipient"`
	Bundle    BundleProof         `json:"bundle"`
	Records   []RecordProof       `json:"records"`
	Fence     string              `json:"fence,omitempty"`
}
type WrappingIdentity struct {
	Public  string `json:"public"`
	Private string `json:"private,omitempty"`
}
type BundleProof struct {
	Digest string `json:"digest"`
	Cipher string `json:"cipher"`
}
type RecordProof struct {
	ID   string `json:"id"`
	Hash string `json:"hash"`
}
type ImportMarker struct {
	TransferID string `json:"transfer_id"`
}

func RecordHash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (r *VaultKeyRepository) LoadImport(ctx context.Context, id string) (*ImportState, error) {
	entry, err := r.storage.Get(ctx, importPrefix+"receivers/"+id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, ErrImportNotFound
	}
	var state ImportState
	if err := enc.StrictUnmarshalJSON(entry.Value, &state); err != nil {
		return nil, fmt.Errorf("invalid custody import state")
	}
	if state.Format != 0 && state.Format != ImportFormat {
		return nil, fmt.Errorf("unsupported custody import format")
	}
	if state.Selection.TransferID != id {
		return nil, fmt.Errorf("custody import identity differs")
	}
	return &state, nil
}
func (r *VaultKeyRepository) SaveImport(ctx context.Context, state *ImportState) error {
	entry, err := logical.StorageEntryJSON(importPrefix+"receivers/"+state.Selection.TransferID, state)
	if err != nil {
		return err
	}
	return r.storage.Put(ctx, entry)
}
func (r *VaultKeyRepository) marker(ctx context.Context, id string) (*ImportMarker, error) {
	entry, err := r.storage.Get(ctx, importPrefix+"keys/"+id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, errMarkerNotFound
	}
	var marker ImportMarker
	if err := enc.StrictUnmarshalJSON(entry.Value, &marker); err != nil || marker.TransferID == "" {
		return nil, fmt.Errorf("invalid custody import marker")
	}
	return &marker, nil
}

type recordLocation struct {
	path   string
	active bool
}

func stagedPath(transfer, id string) string { return importPrefix + "records/" + transfer + "/" + id }
func (r *VaultKeyRepository) location(ctx context.Context, id string) (recordLocation, error) {
	marker, err := r.marker(ctx, id)
	if errors.Is(err, errMarkerNotFound) {
		return recordLocation{path: keyPath(id), active: true}, nil
	}
	if err != nil {
		return recordLocation{}, err
	}
	state, err := r.LoadImport(ctx, marker.TransferID)
	if err != nil && !errors.Is(err, ErrImportNotFound) {
		return recordLocation{}, err
	}
	if state != nil && state.Phase == "active" {
		for _, proof := range state.Records {
			if proof.ID == id {
				return recordLocation{path: keyPath(id), active: true}, nil
			}
		}
		return recordLocation{}, fmt.Errorf("custody key missing from import receipt")
	}
	// Previous receivers stored staged material in keys/. Read them inactive only;
	// activation requires abort/reimport, never an implicit format conversion.
	if state != nil && state.Format == 0 {
		return recordLocation{path: keyPath(id)}, nil
	}
	return recordLocation{path: stagedPath(marker.TransferID, id)}, nil
}
func (r *VaultKeyRepository) importActive(ctx context.Context, id string) (bool, error) {
	location, err := r.location(ctx, id)
	return location.active, err
}

// ValidateRecord validates both legacy and current records without rewriting
// bytes, timestamps, policies, or key material. External handles are not portable.
func (r *VaultKeyRepository) ValidateRecord(id string, raw []byte) error {
	var key domain.Key
	if err := enc.StrictUnmarshalJSON(raw, &key); err != nil {
		return ErrInvalidPolicyRecord
	}
	key, err := r.normalize(key, id)
	if err != nil {
		return err
	}
	if key.CustodyMode != v1.CustodyModeMVP {
		return faults.New(faults.Unsupported, "external signer custody cannot be transferred")
	}
	return nil
}
func (r *VaultKeyRepository) ExportRecord(ctx context.Context, id string) ([]byte, error) {
	enabled, err := r.importActive(ctx, id)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, faults.New(faults.Conflict, "custody import is not active")
	}
	entry, err := r.storage.Get(ctx, keyPath(id))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, faults.New(faults.NotFound, "selected key is absent")
	}
	if err := r.ValidateRecord(id, entry.Value); err != nil {
		return nil, err
	}
	return bytes.Clone(entry.Value), nil
}

// CheckStage rejects all live-key collisions before any staged record is written.
func (r *VaultKeyRepository) CheckStage(ctx context.Context, transfer string, proof RecordProof) error {
	marker, err := r.marker(ctx, proof.ID)
	if err != nil && !errors.Is(err, errMarkerNotFound) {
		return err
	}
	if marker != nil && marker.TransferID != transfer {
		return faults.New(faults.Conflict, "key belongs to another custody import")
	}
	live, err := r.storage.Get(ctx, keyPath(proof.ID))
	if err != nil {
		return err
	}
	if live != nil {
		return faults.New(faults.Conflict, "target custody key conflicts")
	}
	entry, err := r.storage.Get(ctx, stagedPath(transfer, proof.ID))
	if err != nil {
		return err
	}
	if entry != nil && (marker == nil || RecordHash(entry.Value) != proof.Hash) {
		return faults.New(faults.Conflict, "staged custody key conflicts")
	}
	return nil
}
func (r *VaultKeyRepository) StageRecord(ctx context.Context, transfer, id string, raw []byte) error {
	if err := r.CheckStage(ctx, transfer, RecordProof{ID: id, Hash: RecordHash(raw)}); err != nil {
		return err
	}
	marker, err := logical.StorageEntryJSON(importPrefix+"keys/"+id, ImportMarker{TransferID: transfer})
	if err != nil {
		return err
	}
	if err := r.storage.Put(ctx, marker); err != nil {
		return err
	}
	// No Source key material is written to keys/ before the durable fence. A
	// downgraded signer cannot discover or enable these records through its API.
	return r.storage.Put(ctx, &logical.StorageEntry{Key: stagedPath(transfer, id), Value: bytes.Clone(raw)})
}
func (r *VaultKeyRepository) VerifyImport(ctx context.Context, state *ImportState) error {
	if state.Format != ImportFormat {
		return faults.New(faults.Conflict, "legacy custody receiver must be aborted and prepared again")
	}
	for _, proof := range state.Records {
		if err := r.verifyOwned(ctx, state, proof, false); err != nil {
			return err
		}
		live, err := r.storage.Get(ctx, keyPath(proof.ID))
		if err != nil {
			return err
		}
		if live != nil && (state.Phase != "activating" || state.Fence == "" || RecordHash(live.Value) != proof.Hash) {
			return faults.New(faults.Conflict, "target custody key conflicts")
		}
	}
	return nil
}
func (r *VaultKeyRepository) verifyOwned(ctx context.Context, state *ImportState, proof RecordProof, allowMissing bool) error {
	marker, err := r.marker(ctx, proof.ID)
	if err != nil && !errors.Is(err, errMarkerNotFound) {
		return err
	}
	path := stagedPath(state.Selection.TransferID, proof.ID)
	if state.Format == 0 {
		path = keyPath(proof.ID)
	}
	entry, err := r.storage.Get(ctx, path)
	if err != nil {
		return err
	}
	if marker == nil {
		if allowMissing && (entry == nil || state.Format == 0) {
			return nil
		}
		return faults.New(faults.Conflict, "custody import marker differs")
	}
	if marker.TransferID != state.Selection.TransferID {
		return faults.New(faults.Conflict, "custody import marker differs")
	}
	if entry == nil && allowMissing {
		return nil
	}
	if entry == nil || RecordHash(entry.Value) != proof.Hash {
		return faults.New(faults.Conflict, "custody import readback differs")
	}
	return nil
}

// MaterializeImport runs only after an immutable Source fence attestation has
// been persisted. Until the final active phase, this backend still gates every
// member inactive. A retry never overwrites a foreign or modified live record.
func (r *VaultKeyRepository) MaterializeImport(ctx context.Context, state *ImportState) error {
	if state.Phase != "activating" || state.Fence == "" {
		return faults.New(faults.Conflict, "custody activation fence is absent")
	}
	if err := r.VerifyImport(ctx, state); err != nil {
		return err
	}
	for _, proof := range state.Records {
		live, err := r.storage.Get(ctx, keyPath(proof.ID))
		if err != nil {
			return err
		}
		if live != nil {
			continue
		}
		original, err := r.storage.Get(ctx, stagedPath(state.Selection.TransferID, proof.ID))
		if err != nil {
			return err
		}
		if original == nil || RecordHash(original.Value) != proof.Hash {
			return faults.New(faults.Conflict, "custody import readback differs")
		}
		if err := r.storage.Put(ctx, &logical.StorageEntry{Key: keyPath(proof.ID), Value: bytes.Clone(original.Value)}); err != nil {
			return err
		}
	}
	for _, proof := range state.Records {
		entry, err := r.storage.Get(ctx, keyPath(proof.ID))
		if err != nil {
			return err
		}
		if entry == nil || RecordHash(entry.Value) != proof.Hash {
			return faults.New(faults.Conflict, "custody activation readback differs")
		}
	}
	return nil
}
func (r *VaultKeyRepository) RemoveStaged(ctx context.Context, state *ImportState) error {
	for _, proof := range state.Records {
		if err := r.verifyOwned(ctx, state, proof, true); err != nil {
			return err
		}
	}
	for _, proof := range state.Records {
		marker, err := r.marker(ctx, proof.ID)
		if errors.Is(err, errMarkerNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if marker.TransferID != state.Selection.TransferID {
			return faults.New(faults.Conflict, "custody import marker differs")
		}
		path := stagedPath(state.Selection.TransferID, proof.ID)
		if state.Format == 0 {
			path = keyPath(proof.ID)
		} // Owned, unchanged previous-format staged record.
		if err := r.storage.Delete(ctx, path); err != nil {
			return err
		}
		if err := r.storage.Delete(ctx, importPrefix+"keys/"+proof.ID); err != nil {
			return err
		}
	}
	return nil
}
