package v1

// CustodySelection binds a selected key set to an operator's Source checkpoint.
// A checkpoint identifies evidence; it does not establish that Source is fenced.
type CustodySelection struct {
	TransferID string   `json:"transfer_id"`
	Checkpoint string   `json:"checkpoint"`
	KeyIDs     []string `json:"key_ids"`
}

type CustodyExportRequest struct {
	Selection CustodySelection `json:"selection"`
	Recipient string           `json:"recipient"`
}

type CustodyImportRequest struct {
	TransferID string `json:"transfer_id"`
	Ciphertext []byte `json:"ciphertext"`
	Digest     string `json:"digest"`
}

// CustodyActivation records a trusted operator's handover evidence. The plugin
// cannot observe the Source scheduler or independently establish its fence.
type CustodyActivation struct {
	TransferID string `json:"transfer_id"`
	Digest     string `json:"digest"`
	Fence      string `json:"fence"`
}

type CustodyReference struct {
	TransferID string `json:"transfer_id"`
}

type CustodyReceipt struct {
	TransferID string `json:"transfer_id"`
	Checkpoint string `json:"checkpoint"`
	Recipient  string `json:"recipient"`
	Phase      string `json:"phase"`
	Digest     string `json:"digest,omitempty"`
	Count      int    `json:"count"`
	Fence      string `json:"fence,omitempty"`
}

type CustodyExportResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Digest     string `json:"digest"`
	Count      int    `json:"count"`
}
