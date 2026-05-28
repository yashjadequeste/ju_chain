package models

type Certificate struct {
	DocID            string `json:"docID"`
	Hash             string `json:"hash"`
	StudentID        string `json:"studentID"`
	IssuerID         string `json:"issuerID"`
	Timestamp        int64  `json:"timestamp"`
	RevokedTimestamp int64  `json:"revokedTimestamp"`
	Status           string `json:"status"`
	RevocationReason string `json:"revocationReason"`
	// FrozenTimestamp / UnfrozenTimestamp / FreezeReason capture the
	// freeze-unfreeze lifecycle. A FROZEN credential remains on the ledger
	// and is still verifiable, but verification UIs render it as "on hold"
	// (download is disabled). Revoke and Freeze are independent states:
	// freeze must be lifted before a credential can be revoked.
	FrozenTimestamp   int64  `json:"frozenTimestamp"`
	UnfrozenTimestamp int64  `json:"unfrozenTimestamp"`
	FreezeReason      string `json:"freezeReason"`
	// Reissue tracking
	Version           int    `json:"version"`
	OriginalDocID     string `json:"originalDocID"`
	PreviousDocID     string `json:"previousDocID"`
	ReissuedToDocID   string `json:"reissuedToDocID"`
	ReissuedTimestamp int64  `json:"reissuedTimestamp"`
	ReissueReason     string `json:"reissueReason"`
	// JsonContent stores the full credential subject row (name, course,
	// grades, marks, etc.) as a JSON string so the verification UI can
	// render the entire certificate on a QR scan. The on-chain Hash is
	// always derived from this canonical JSON.
	JsonContent string `json:"jsonContent"`
}

type ReissueHistoryRecord struct {
	Version       int                    `json:"version"`
	DocID         string                 `json:"docID"`
	Hash          string                 `json:"hash"`
	StudentID     string                 `json:"studentID"`
	JsonContent   string                 `json:"jsonContent"`
	ChangedFields map[string]interface{} `json:"changedFields,omitempty"`
	ReissuedBy    string                 `json:"reissuedBy"`
	ReissuedAt    int64                  `json:"reissuedAt"`
	Reason        string                 `json:"reason"`
}

type PrivateDocumentDetails struct {
	DocID            string `json:"docID"`
	StudentID        string `json:"studentID"`
	IssuerID         string `json:"issuerID"`
	RevocationReason string `json:"revocationReason"`
}

// DocumentChange captures a single field diff for audit trails.
type DocumentChange struct {
	Field    string      `json:"field"`
	OldValue interface{} `json:"oldValue"`
	NewValue interface{} `json:"newValue"`
}

// BatchDocumentItem is a single entry inside a RegisterDocumentBatch call.
type BatchDocumentItem struct {
	DocID       string `json:"docID"`
	Hash        string `json:"hash"`
	StudentID   string `json:"studentID"`
	IssuerID    string `json:"issuerID"`
	JsonContent string `json:"jsonContent,omitempty"`
}

// BatchRegistrationResult is returned for each item in a batch call.
type BatchRegistrationResult struct {
	DocID   string `json:"docID"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// VerificationTimeWindow stores a global start/end unix timestamp that
// restricts when credentials may be verified. A nil/absent window means
// verification is always allowed.
type VerificationTimeWindow struct {
	StartUnix int64 `json:"startUnix"`
	EndUnix   int64 `json:"endUnix"`
}

// TenantVerificationSettings — per-institute verification portal policy on ledger.
// Stored at TENANT~SETTINGS~{tenantId}.
type TenantVerificationSettings struct {
	TenantID                      string `json:"tenantId"`
	RequireVerifierAccessApproval bool   `json:"requireVerifierAccessApproval"`
	UpdatedAt                     int64  `json:"updatedAt"`
	UpdatedBy                     string `json:"updatedBy"`
}

// VerifierAccessRequest — verifier view-access grant workflow (RBAC on ledger).
// Stored at VERIFIER~ACCESS~{verifierId}~{credentialId}.
type VerifierAccessRequest struct {
	VerifierID     string `json:"verifierId"`
	CredentialID   string `json:"credentialId"`
	TenantID       string `json:"tenantId"`
	Status         string `json:"status"`
	Source         string `json:"source"`
	VerifierEmail  string `json:"verifierEmail"`
	VerifierName   string `json:"verifierName"`
	VerifierMobile string `json:"verifierMobile"`
	DecidedBy      string `json:"decidedBy"`
	DeclineReason  string `json:"declineReason"`
	RequestedAt    int64  `json:"requestedAt"`
	DecidedAt      int64  `json:"decidedAt"`
}
