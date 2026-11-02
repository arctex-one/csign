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

var ErrImportNotFound = errors.New("custody receiver not found")
var errMarkerNotFound = errors.New("custody import marker not found")

// ImportState is stored only within this mount's encrypted Vault storage. Its
// wrapping identity is discarded after staging or abort, never returned by API.
type ImportState struct {
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
func (r *VaultKeyRepository) importActive(ctx context.Context, id string) (bool, error) {
	marker, err := r.marker(ctx, id)
	if errors.Is(err, errMarkerNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	state, err := r.LoadImport(ctx, marker.TransferID)
	if errors.Is(err, ErrImportNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if state.Phase != "active" {
		return false, nil
	}
	for _, proof := range state.Records {
		if proof.ID == id {
			return true, nil
		}
	}
	return false, fmt.Errorf("custody key missing from import receipt")
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

// CheckStage rejects every foreign collision before any key is written. A retry
// may reuse only this transfer's marker and exactly identical original bytes.
func (r *VaultKeyRepository) CheckStage(ctx context.Context, transfer string, proof RecordProof) error {
	marker, err := r.marker(ctx, proof.ID)
	if errors.Is(err, errMarkerNotFound) {
		err = nil
	}
	if err != nil {
		return err
	}
	if marker != nil && marker.TransferID != transfer {
		return faults.New(faults.Conflict, "key belongs to another custody import")
	}
	entry, err := r.storage.Get(ctx, keyPath(proof.ID))
	if err != nil {
		return err
	}
	if entry != nil && (marker == nil || RecordHash(entry.Value) != proof.Hash) {
		return faults.New(faults.Conflict, "target custody key conflicts")
	}
	return nil
}
func (r *VaultKeyRepository) StageRecord(ctx context.Context, transfer, id string, raw []byte) error {
	if err := r.CheckStage(ctx, transfer, RecordProof{ID: id, Hash: RecordHash(raw)}); err != nil {
		return err
	}
	// Write the gate first: a crash must never leave an ungated imported key.
	marker, err := logical.StorageEntryJSON(importPrefix+"keys/"+id, ImportMarker{TransferID: transfer})
	if err != nil {
		return err
	}
	if err := r.storage.Put(ctx, marker); err != nil {
		return err
	}
	return r.storage.Put(ctx, &logical.StorageEntry{Key: keyPath(id), Value: bytes.Clone(raw)})
}
func (r *VaultKeyRepository) VerifyImport(ctx context.Context, state *ImportState) error {
	for _, proof := range state.Records {
		marker, err := r.marker(ctx, proof.ID)
		if err != nil {
			return err
		}
		if marker == nil || marker.TransferID != state.Selection.TransferID {
			return faults.New(faults.Conflict, "custody import marker differs")
		}
		entry, err := r.storage.Get(ctx, keyPath(proof.ID))
		if err != nil {
			return err
		}
		if entry == nil || RecordHash(entry.Value) != proof.Hash {
			return faults.New(faults.Conflict, "custody import readback differs")
		}
	}
	return nil
}
func (r *VaultKeyRepository) RemoveStaged(ctx context.Context, state *ImportState) error {
	// Preflight all records before removing anything; incomplete copies may have
	// a marker without a key, or no marker yet.
	for _, proof := range state.Records {
		if err := r.CheckStage(ctx, state.Selection.TransferID, proof); err != nil {
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
		if marker == nil {
			continue
		}
		if err := r.storage.Delete(ctx, keyPath(proof.ID)); err != nil {
			return err
		}
		if err := r.storage.Delete(ctx, importPrefix+"keys/"+proof.ID); err != nil {
			return err
		}
	}
	return nil
}
