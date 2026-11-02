package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"slices"

	"filippo.io/age"
	enc "github.com/lazysteff/csign/v2/internal/encoding"
	"github.com/lazysteff/csign/v2/internal/faults"
	"github.com/lazysteff/csign/v2/internal/keyid"
	"github.com/lazysteff/csign/v2/internal/repository"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

// These protocol limits are fixed, not runtime configuration. Vault separately
// enforces its request body limit. Callers can transfer disjoint bounded batches.
const maxCustodyBytes = 8 << 20
const maxCustodyKeys = 1024

var transferIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type HandoffService struct {
	repo *repository.VaultKeyRepository
}
type custodyBundle struct {
	Version   int                 `json:"version"`
	Selection v1.CustodySelection `json:"selection"`
	Recipient string              `json:"recipient"`
	Records   []custodyRecord     `json:"records"`
}
type custodyRecord struct {
	ID  string `json:"id"`
	Raw []byte `json:"raw"`
}

func NewHandoffService(repo *repository.VaultKeyRepository) *HandoffService {
	return &HandoffService{repo: repo}
}
func invalidTransfer() error  { return faults.New(faults.Invalid, "invalid custody transfer") }
func transferConflict() error { return faults.New(faults.Conflict, "custody transfer state differs") }
func validDigest(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && s == hex.EncodeToString(raw)
}
func validateSelection(selection v1.CustodySelection) error {
	if !transferIDPattern.MatchString(selection.TransferID) || !validDigest(selection.Checkpoint) || len(selection.KeyIDs) == 0 || len(selection.KeyIDs) > maxCustodyKeys {
		return invalidTransfer()
	}
	for i, id := range selection.KeyIDs {
		if len(id) > 256 || keyid.Validate(id) != nil || (i > 0 && selection.KeyIDs[i-1] >= id) {
			return invalidTransfer()
		}
	}
	return nil
}
func receipt(state *repository.ImportState) v1.CustodyReceipt {
	return v1.CustodyReceipt{TransferID: state.Selection.TransferID, Checkpoint: state.Selection.Checkpoint, Recipient: state.Recipient.Public, Phase: state.Phase, Digest: state.Bundle.Digest, Count: len(state.Selection.KeyIDs), Fence: state.Fence}
}
func (s *HandoffService) load(ctx context.Context, id string) (*repository.ImportState, error) {
	if !transferIDPattern.MatchString(id) {
		return nil, invalidTransfer()
	}
	state, err := s.repo.LoadImport(ctx, id)
	if errors.Is(err, repository.ErrImportNotFound) {
		return nil, faults.New(faults.NotFound, "custody receiver not found")
	}
	if err != nil {
		return nil, err
	}
	return state, nil
}
func (s *HandoffService) Prepare(ctx context.Context, selection v1.CustodySelection) (v1.CustodyReceipt, error) {
	if err := validateSelection(selection); err != nil {
		return v1.CustodyReceipt{}, err
	}
	existing, err := s.repo.LoadImport(ctx, selection.TransferID)
	if errors.Is(err, repository.ErrImportNotFound) {
		err = nil
	}
	if err != nil {
		return v1.CustodyReceipt{}, err
	}
	if existing != nil {
		if !reflect.DeepEqual(existing.Selection, selection) {
			return v1.CustodyReceipt{}, transferConflict()
		}
		return receipt(existing), nil
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return v1.CustodyReceipt{}, err
	}
	state := &repository.ImportState{Format: repository.ImportFormat, Selection: selection, Phase: "prepared", Recipient: repository.WrappingIdentity{Public: identity.Recipient().String(), Private: identity.String()}}
	if err := s.repo.SaveImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	return receipt(state), nil
}
func (s *HandoffService) Export(ctx context.Context, req v1.CustodyExportRequest) (v1.CustodyExportResponse, error) {
	if err := validateSelection(req.Selection); err != nil {
		return v1.CustodyExportResponse{}, err
	}
	recipient, err := age.ParseX25519Recipient(req.Recipient)
	if err != nil {
		return v1.CustodyExportResponse{}, invalidTransfer()
	}
	bundle := custodyBundle{Version: 1, Selection: req.Selection, Recipient: req.Recipient}
	defer func() {
		for _, record := range bundle.Records {
			clear(record.Raw)
		}
	}()
	size := 0
	for _, id := range req.Selection.KeyIDs {
		raw, err := s.repo.ExportRecord(ctx, id)
		if err != nil {
			return v1.CustodyExportResponse{}, err
		}
		size += len(raw)
		if size > maxCustodyBytes {
			return v1.CustodyExportResponse{}, invalidTransfer()
		}
		bundle.Records = append(bundle.Records, custodyRecord{ID: id, Raw: raw})
	}
	plaintext, err := json.Marshal(bundle)
	if err != nil {
		return v1.CustodyExportResponse{}, err
	}
	defer clear(plaintext)
	if len(plaintext) > maxCustodyBytes {
		return v1.CustodyExportResponse{}, invalidTransfer()
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return v1.CustodyExportResponse{}, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		return v1.CustodyExportResponse{}, err
	}
	if err := writer.Close(); err != nil {
		return v1.CustodyExportResponse{}, err
	}
	return v1.CustodyExportResponse{Ciphertext: ciphertext.Bytes(), Digest: repository.RecordHash(plaintext), Count: len(bundle.Records)}, nil
}
func (s *HandoffService) Import(ctx context.Context, req v1.CustodyImportRequest) (v1.CustodyReceipt, error) {
	if !validDigest(req.Digest) || len(req.Ciphertext) == 0 || len(req.Ciphertext) > maxCustodyBytes+65536 {
		return v1.CustodyReceipt{}, invalidTransfer()
	}
	state, err := s.load(ctx, req.TransferID)
	if err != nil {
		return v1.CustodyReceipt{}, err
	}
	proof := repository.BundleProof{Digest: req.Digest, Cipher: repository.RecordHash(req.Ciphertext)}
	if state.Phase != "prepared" && state.Bundle != proof {
		return v1.CustodyReceipt{}, transferConflict()
	}
	if state.Phase == "prepared" {
		state.Format = repository.ImportFormat
	}
	if state.Phase != "active" && state.Format != repository.ImportFormat {
		return v1.CustodyReceipt{}, transferConflict()
	}
	switch state.Phase {
	case "staged":
		if err := s.repo.VerifyImport(ctx, state); err != nil {
			return v1.CustodyReceipt{}, err
		}
		return receipt(state), nil
	case "active":
		return receipt(state), nil // Immutable receipt; active keys may have normal policy updates.
	case "prepared", "importing":
	default:
		return v1.CustodyReceipt{}, transferConflict()
	}
	bundle, err := s.open(state, req)
	if err != nil {
		return v1.CustodyReceipt{}, err
	}
	defer func() {
		for _, record := range bundle.Records {
			clear(record.Raw)
		}
	}()
	proofs := make([]repository.RecordProof, 0, len(bundle.Records))
	for _, record := range bundle.Records {
		if err := s.repo.ValidateRecord(record.ID, record.Raw); err != nil {
			return v1.CustodyReceipt{}, err
		}
		item := repository.RecordProof{ID: record.ID, Hash: repository.RecordHash(record.Raw)}
		if err := s.repo.CheckStage(ctx, req.TransferID, item); err != nil {
			return v1.CustodyReceipt{}, err
		}
		proofs = append(proofs, item)
	}
	if state.Phase == "importing" && !reflect.DeepEqual(state.Records, proofs) {
		return v1.CustodyReceipt{}, transferConflict()
	}
	state.Phase = "importing"
	state.Bundle = proof
	state.Records = proofs
	if err := s.repo.SaveImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	for _, record := range bundle.Records {
		if err := s.repo.StageRecord(ctx, req.TransferID, record.ID, record.Raw); err != nil {
			return v1.CustodyReceipt{}, err
		}
	}
	if err := s.repo.VerifyImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	state.Phase = "staged"
	state.Recipient.Private = ""
	if err := s.repo.SaveImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	return receipt(state), nil
}
func (s *HandoffService) open(state *repository.ImportState, req v1.CustodyImportRequest) (*custodyBundle, error) {
	identity, err := age.ParseX25519Identity(state.Recipient.Private)
	if err != nil {
		return nil, invalidTransfer()
	}
	reader, err := age.Decrypt(bytes.NewReader(req.Ciphertext), identity)
	if err != nil {
		return nil, invalidTransfer()
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, maxCustodyBytes+1))
	defer clear(plaintext)
	if err != nil || len(plaintext) > maxCustodyBytes || repository.RecordHash(plaintext) != req.Digest {
		return nil, invalidTransfer()
	}
	var bundle custodyBundle
	if enc.StrictUnmarshalJSON(plaintext, &bundle) != nil {
		return nil, invalidTransfer()
	}
	if bundle.Version != 1 || bundle.Recipient != state.Recipient.Public || !reflect.DeepEqual(bundle.Selection, state.Selection) || len(bundle.Records) != len(state.Selection.KeyIDs) {
		return nil, invalidTransfer()
	}
	ids := make([]string, 0, len(bundle.Records))
	for _, record := range bundle.Records {
		ids = append(ids, record.ID)
	}
	if !slices.Equal(ids, state.Selection.KeyIDs) {
		return nil, invalidTransfer()
	}
	return &bundle, nil
}
func (s *HandoffService) Activate(ctx context.Context, req v1.CustodyActivation) (v1.CustodyReceipt, error) {
	if !validDigest(req.Fence) || !validDigest(req.Digest) {
		return v1.CustodyReceipt{}, invalidTransfer()
	}
	state, err := s.load(ctx, req.TransferID)
	if err != nil {
		return v1.CustodyReceipt{}, err
	}
	if state.Bundle.Digest != req.Digest {
		return v1.CustodyReceipt{}, transferConflict()
	}
	if state.Phase == "active" {
		if state.Fence != req.Fence {
			return v1.CustodyReceipt{}, transferConflict()
		}
		return receipt(state), nil
	}
	if state.Phase != "staged" && state.Phase != "activating" {
		return v1.CustodyReceipt{}, transferConflict()
	}
	if state.Phase == "activating" && state.Fence != req.Fence {
		return v1.CustodyReceipt{}, transferConflict()
	}
	if err := s.repo.VerifyImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	if state.Phase == "staged" {
		// This durable attestation precedes the first write to the live key store.
		// Activation is now forward-only: retain the Source fence and resume here.
		state.Phase = "activating"
		state.Fence = req.Fence
		if err := s.repo.SaveImport(ctx, state); err != nil {
			return v1.CustodyReceipt{}, err
		}
	}
	if err := s.repo.MaterializeImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	// One final phase transition opens the complete verified set in this backend.
	state.Phase = "active"
	if err := s.repo.SaveImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	return receipt(state), nil
}
func (s *HandoffService) Abort(ctx context.Context, req v1.CustodyReference) (v1.CustodyReceipt, error) {
	state, err := s.load(ctx, req.TransferID)
	if err != nil {
		return v1.CustodyReceipt{}, err
	}
	if state.Phase == "active" || state.Phase == "activating" {
		return v1.CustodyReceipt{}, transferConflict()
	}
	if state.Phase == "aborted" {
		return receipt(state), nil
	}
	state.Phase = "aborting"
	if err := s.repo.SaveImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	if err := s.repo.RemoveStaged(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	state.Phase = "aborted"
	state.Recipient.Private = ""
	if err := s.repo.SaveImport(ctx, state); err != nil {
		return v1.CustodyReceipt{}, err
	}
	return receipt(state), nil
}
func (s *HandoffService) Status(ctx context.Context, req v1.CustodyReference) (v1.CustodyReceipt, error) {
	state, err := s.load(ctx, req.TransferID)
	if err != nil {
		return v1.CustodyReceipt{}, err
	}
	return receipt(state), nil
}
