package chaincode

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"justifai_chaincode/models"
	"justifai_chaincode/utils"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	StatusActive   = "ACTIVE"
	StatusRevoked  = "REVOKED"
	StatusFrozen   = "FROZEN"
	StatusReissued = "REISSUED"

	EventDocumentRegistered      = "DocumentRegistered"
	EventDocumentRevoked         = "DocumentRevoked"
	EventDocumentFrozen          = "DocumentFrozen"
	EventDocumentUnfrozen        = "DocumentUnfrozen"
	EventDocumentReissued        = "DocumentReissued"
	EventDocumentBatchRegistered = "DocumentBatchRegistered"

	HashDocCompositeKey        = "hash~docID"
	ReissueHistoryCompositeKey = "reissue~docID~version"
	PrivateDataCollection      = "documentPrivateDetails"

	// GlobalStateKeyVerificationWindow is the fixed state key for the
	// optional verification time-window config.
	GlobalStateKeyVerificationWindow = "GLOBAL~VERIFICATION~TIME~WINDOW"
)

var (
	registerDocumentRoles = []string{"ISSUER_ORG", "ADMIN_ORG", "ISSUER", "UNIVERSITY_ADMIN", "ORG1"}
	revokeDocumentRoles   = []string{"ADMIN_ORG", "UNIVERSITY_ADMIN", "ORG1"}
	freezeDocumentRoles   = []string{"ADMIN_ORG", "UNIVERSITY_ADMIN", "ORG1"}
	reissueDocumentRoles  = []string{"ADMIN_ORG", "ISSUER_ORG", "UNIVERSITY_ADMIN", "ORG1", "ISSUER"}
	readDocumentRoles     = []string{"ISSUER_ORG", "VERIFIER_ORG", "ADMIN_ORG", "ISSUER", "VERIFIER", "UNIVERSITY_ADMIN", "ORG1"}
)

type CertificateContract struct {
	contractapi.Contract
}

type VerificationResponse struct {
	Exists   bool                `json:"exists"`
	Document *models.Certificate `json:"document,omitempty"`
}

type HistoryRecord struct {
	TxID      string              `json:"txID"`
	Timestamp int64               `json:"timestamp"`
	IsDelete  bool                `json:"isDelete"`
	Document  *models.Certificate `json:"document,omitempty"`
}

type PrivateDocumentResponse struct {
	Document       *models.Certificate            `json:"document"`
	PrivateDetails *models.PrivateDocumentDetails `json:"privateDetails,omitempty"`
}

// RegisterDocument registers a public document with only the on-chain hash.
// Use RegisterDocumentWithContent when the full credential subject (CSV row
// data such as name, course, marks) should also be stored on-chain so QR-scan
// verification UIs can show the entire certificate.
func (c *CertificateContract) RegisterDocument(ctx contractapi.TransactionContextInterface, docID string, hash string, studentID string, issuerID string) error {
	return c.registerDocumentInternal(ctx, docID, hash, studentID, issuerID, "")
}

// RegisterDocumentWithContent registers a document and also persists the full
// credential subject as a canonical JSON string in `jsonContent`. The on-chain
// `hash` MUST be the SHA-256 of the same canonical JSON. Verifiers can fetch
// the full subject directly from the ledger (CouchDB state DB) on a QR scan
// without any off-chain mirror.
func (c *CertificateContract) RegisterDocumentWithContent(ctx contractapi.TransactionContextInterface, docID string, hash string, studentID string, issuerID string, jsonContent string) error {
	return c.registerDocumentInternal(ctx, docID, hash, studentID, issuerID, jsonContent)
}

func (c *CertificateContract) registerDocumentInternal(ctx contractapi.TransactionContextInterface, docID string, hash string, studentID string, issuerID string, jsonContent string) error {
	if err := utils.AuthorizeWithMSP(ctx, registerDocumentRoles); err != nil {
		return err
	}

	if docID == "" || hash == "" || studentID == "" {
		return fmt.Errorf("docID, hash and studentID are required")
	}
	normalizedHash, err := normalizeSHA256Hash(hash)
	if err != nil {
		return err
	}

	exists, err := c.documentExists(ctx, docID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("document %s already exists", docID)
	}

	if issuerID == "" {
		var err error
		issuerID, err = utils.GetClientMSPID(ctx)
		if err != nil {
			return err
		}
	}

	if jsonContent != "" {
		var probe map[string]interface{}
		if err := json.Unmarshal([]byte(jsonContent), &probe); err != nil {
			return fmt.Errorf("jsonContent must be valid JSON: %w", err)
		}
	}

	txTimestamp, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return err
	}

	document := models.Certificate{
		DocID:         docID,
		Hash:          normalizedHash,
		StudentID:     studentID,
		IssuerID:      issuerID,
		Timestamp:     txTimestamp,
		Status:        StatusActive,
		Version:       1,
		OriginalDocID: docID,
		JsonContent:   jsonContent,
	}

	documentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	if err := ctx.GetStub().PutState(docID, documentJSON); err != nil {
		return fmt.Errorf("failed to store document: %w", err)
	}

	hashDocKey, err := ctx.GetStub().CreateCompositeKey(HashDocCompositeKey, []string{normalizedHash, docID})
	if err != nil {
		return fmt.Errorf("failed to create hash index key: %w", err)
	}
	if err := ctx.GetStub().PutState(hashDocKey, []byte{0x00}); err != nil {
		return fmt.Errorf("failed to store hash index: %w", err)
	}

	if err := ctx.GetStub().SetEvent(EventDocumentRegistered, documentJSON); err != nil {
		return fmt.Errorf("failed to emit %s event: %w", EventDocumentRegistered, err)
	}

	return nil
}

func (c *CertificateContract) RegisterDocumentPrivate(ctx contractapi.TransactionContextInterface, docID string, hash string, studentID string, issuerID string) error {
	if err := utils.AuthorizeWithMSP(ctx, registerDocumentRoles); err != nil {
		return err
	}

	if docID == "" || hash == "" || studentID == "" {
		return fmt.Errorf("docID, hash and studentID are required")
	}
	normalizedHash, err := normalizeSHA256Hash(hash)
	if err != nil {
		return err
	}

	exists, err := c.documentExists(ctx, docID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("document %s already exists", docID)
	}

	if issuerID == "" {
		issuerID, err = utils.GetClientMSPID(ctx)
		if err != nil {
			return err
		}
	}

	txTimestamp, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return err
	}

	publicDocument := models.Certificate{
		DocID:         docID,
		Hash:          normalizedHash,
		Timestamp:     txTimestamp,
		Status:        StatusActive,
		Version:       1,
		OriginalDocID: docID,
	}
	publicDocumentJSON, err := json.Marshal(publicDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal public document: %w", err)
	}

	privateDetails := models.PrivateDocumentDetails{
		DocID:     docID,
		StudentID: studentID,
		IssuerID:  issuerID,
	}
	privateDetailsJSON, err := json.Marshal(privateDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal private document details: %w", err)
	}

	if err := ctx.GetStub().PutState(docID, publicDocumentJSON); err != nil {
		return fmt.Errorf("failed to store public document: %w", err)
	}
	if err := ctx.GetStub().PutPrivateData(PrivateDataCollection, docID, privateDetailsJSON); err != nil {
		return fmt.Errorf("failed to store private document details: %w", err)
	}

	hashDocKey, err := ctx.GetStub().CreateCompositeKey(HashDocCompositeKey, []string{normalizedHash, docID})
	if err != nil {
		return fmt.Errorf("failed to create hash index key: %w", err)
	}
	if err := ctx.GetStub().PutState(hashDocKey, []byte{0x00}); err != nil {
		return fmt.Errorf("failed to store hash index: %w", err)
	}

	if err := ctx.GetStub().SetEvent(EventDocumentRegistered, publicDocumentJSON); err != nil {
		return fmt.Errorf("failed to emit %s event: %w", EventDocumentRegistered, err)
	}

	return nil
}

func (c *CertificateContract) VerifyDocument(ctx contractapi.TransactionContextInterface, docID string) (*VerificationResponse, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}
	if docID == "" {
		return nil, fmt.Errorf("docID is required")
	}

	// Check global verification time window
	inWindow, err := c.IsWithinVerificationWindow(ctx)
	if err != nil {
		return nil, err
	}
	if !inWindow {
		return nil, fmt.Errorf("verification is currently disabled outside the configured time window")
	}

	documentJSON, err := ctx.GetStub().GetState(docID)
	if err != nil {
		return nil, fmt.Errorf("failed to read document %s: %w", docID, err)
	}
	if documentJSON == nil {
		return &VerificationResponse{Exists: false}, nil
	}

	var document models.Certificate
	if err := json.Unmarshal(documentJSON, &document); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document: %w", err)
	}

	return &VerificationResponse{Exists: true, Document: &document}, nil
}

func (c *CertificateContract) VerifyDocumentByHash(ctx contractapi.TransactionContextInterface, hash string) (*VerificationResponse, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}
	normalizedHash, err := normalizeSHA256Hash(hash)
	if err != nil {
		return nil, err
	}

	results, err := ctx.GetStub().GetStateByPartialCompositeKey(HashDocCompositeKey, []string{normalizedHash})
	if err != nil {
		return nil, fmt.Errorf("failed to query hash index: %w", err)
	}
	defer results.Close()

	for results.HasNext() {
		kv, err := results.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate hash index: %w", err)
		}

		_, keyParts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hash index key: %w", err)
		}
		if len(keyParts) != 2 {
			continue
		}

		document, err := c.GetDocument(ctx, keyParts[1])
		if err != nil {
			return nil, err
		}
		return &VerificationResponse{Exists: true, Document: document}, nil
	}

	return &VerificationResponse{Exists: false}, nil
}

func (c *CertificateContract) ValidateHash(ctx contractapi.TransactionContextInterface, docID string, hash string) (bool, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return false, err
	}
	if hash == "" {
		return false, fmt.Errorf("hash is required")
	}
	normalizedHash, err := normalizeSHA256Hash(hash)
	if err != nil {
		return false, err
	}

	document, err := c.GetDocument(ctx, docID)
	if err != nil {
		return false, err
	}

	return document.Hash == normalizedHash, nil
}

func (c *CertificateContract) RevokeDocument(ctx contractapi.TransactionContextInterface, docID string, reason string) error {
	if err := utils.AuthorizeWithMSP(ctx, revokeDocumentRoles); err != nil {
		return err
	}

	if reason == "" {
		return fmt.Errorf("revocation reason is required")
	}

	document, err := c.GetDocument(ctx, docID)
	if err != nil {
		return err
	}

	if document.Status == StatusRevoked {
		return fmt.Errorf("document %s is already revoked", docID)
	}
	if document.Status == StatusFrozen {
		return fmt.Errorf("document %s is frozen; call UnfreezeDocument before revoking", docID)
	}

	txTimestamp, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return err
	}

	document.Status = StatusRevoked
	document.RevocationReason = reason
	document.RevokedTimestamp = txTimestamp

	documentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	if err := ctx.GetStub().PutState(docID, documentJSON); err != nil {
		return fmt.Errorf("failed to update document status: %w", err)
	}
	if err := c.updatePrivateRevocationReason(ctx, docID, reason); err != nil {
		return err
	}

	if err := ctx.GetStub().SetEvent(EventDocumentRevoked, documentJSON); err != nil {
		return fmt.Errorf("failed to emit %s event: %w", EventDocumentRevoked, err)
	}

	return nil
}

// FreezeDocument places an ACTIVE credential into the FROZEN state. A frozen
// credential is still verifiable but downstream UIs render it as "on hold" —
// download is disabled and a banner asks the holder to contact the issuer.
//
// Only ACTIVE → FROZEN is allowed. Frozen credentials must be unfrozen before
// they can be revoked. A FreezeReason is required.
func (c *CertificateContract) FreezeDocument(ctx contractapi.TransactionContextInterface, docID string, reason string) error {
	if err := utils.AuthorizeWithMSP(ctx, freezeDocumentRoles); err != nil {
		return err
	}
	if reason == "" {
		return fmt.Errorf("freeze reason is required")
	}

	document, err := c.GetDocument(ctx, docID)
	if err != nil {
		return err
	}

	switch document.Status {
	case StatusFrozen:
		return fmt.Errorf("document %s is already frozen", docID)
	case StatusRevoked:
		return fmt.Errorf("document %s is revoked and cannot be frozen", docID)
	}

	txTimestamp, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return err
	}

	document.Status = StatusFrozen
	document.FreezeReason = reason
	document.FrozenTimestamp = txTimestamp
	document.UnfrozenTimestamp = 0

	documentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}
	if err := ctx.GetStub().PutState(docID, documentJSON); err != nil {
		return fmt.Errorf("failed to update document status: %w", err)
	}
	if err := ctx.GetStub().SetEvent(EventDocumentFrozen, documentJSON); err != nil {
		return fmt.Errorf("failed to emit %s event: %w", EventDocumentFrozen, err)
	}
	return nil
}

// UnfreezeDocument lifts a FROZEN credential back to ACTIVE. `reason` is
// optional; when empty the previous FreezeReason is preserved on the prior
// history record and cleared from the current state.
func (c *CertificateContract) UnfreezeDocument(ctx contractapi.TransactionContextInterface, docID string, reason string) error {
	if err := utils.AuthorizeWithMSP(ctx, freezeDocumentRoles); err != nil {
		return err
	}

	document, err := c.GetDocument(ctx, docID)
	if err != nil {
		return err
	}
	if document.Status != StatusFrozen {
		return fmt.Errorf("document %s is not frozen (status=%s)", docID, document.Status)
	}

	txTimestamp, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return err
	}

	document.Status = StatusActive
	document.FreezeReason = reason // unfreeze note (or empty)
	document.UnfrozenTimestamp = txTimestamp

	documentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}
	if err := ctx.GetStub().PutState(docID, documentJSON); err != nil {
		return fmt.Errorf("failed to update document status: %w", err)
	}
	if err := ctx.GetStub().SetEvent(EventDocumentUnfrozen, documentJSON); err != nil {
		return fmt.Errorf("failed to emit %s event: %w", EventDocumentUnfrozen, err)
	}
	return nil
}

// ReissueDocument creates a new immutable credential version and marks the old
// credential as REISSUED. The old docID/hash/jsonContent remain intact so old QR
// scans can show exactly what was originally anchored, plus a link to the new ID.
func (c *CertificateContract) ReissueDocument(ctx contractapi.TransactionContextInterface, docID string, newDocID string, newHash string, newJsonContent string, reason string) error {
	if err := utils.AuthorizeWithMSP(ctx, reissueDocumentRoles); err != nil {
		return err
	}
	if docID == "" || newDocID == "" || newHash == "" {
		return fmt.Errorf("docID, newDocID and newHash are required")
	}
	if docID == newDocID {
		return fmt.Errorf("newDocID must be different from docID")
	}
	if reason == "" {
		return fmt.Errorf("reissue reason is required")
	}
	normalizedHash, err := normalizeSHA256Hash(newHash)
	if err != nil {
		return err
	}
	if newJsonContent != "" {
		var probe map[string]interface{}
		if err := json.Unmarshal([]byte(newJsonContent), &probe); err != nil {
			return fmt.Errorf("newJsonContent must be valid JSON: %w", err)
		}
	}

	document, err := c.GetDocument(ctx, docID)
	if err != nil {
		return err
	}
	if document.Status == StatusRevoked {
		return fmt.Errorf("document %s is revoked and cannot be reissued", docID)
	}
	if document.Status == StatusFrozen {
		return fmt.Errorf("document %s is frozen; unfreeze before reissuing", docID)
	}
	if document.Status == StatusReissued {
		return fmt.Errorf("document %s is already reissued to %s", docID, document.ReissuedToDocID)
	}

	exists, err := c.documentExists(ctx, newDocID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("new document %s already exists", newDocID)
	}

	reissuedBy, err := utils.GetClientMSPID(ctx)
	if err != nil {
		return err
	}

	txTimestamp, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return err
	}

	originalDocID := document.OriginalDocID
	if originalDocID == "" {
		originalDocID = document.DocID
	}

	// Compute changed fields for audit trail
	changedFields := make(map[string]interface{})
	if document.Hash != normalizedHash {
		changedFields["hash"] = map[string]string{"old": document.Hash, "new": normalizedHash}
	}
	if document.JsonContent != newJsonContent && newJsonContent != "" {
		changedFields["jsonContent"] = map[string]bool{"changed": true}
	}

	// Store previous version as history record
	record := models.ReissueHistoryRecord{
		Version:       document.Version,
		DocID:         document.DocID,
		Hash:          document.Hash,
		StudentID:     document.StudentID,
		JsonContent:   document.JsonContent,
		ChangedFields: changedFields,
		ReissuedBy:    reissuedBy,
		ReissuedAt:    txTimestamp,
		Reason:        reason,
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal reissue history record: %w", err)
	}
	historyKey, err := ctx.GetStub().CreateCompositeKey(ReissueHistoryCompositeKey, []string{docID, fmt.Sprintf("%d", document.Version)})
	if err != nil {
		return fmt.Errorf("failed to create reissue history key: %w", err)
	}
	if err := ctx.GetStub().PutState(historyKey, recordJSON); err != nil {
		return fmt.Errorf("failed to store reissue history record: %w", err)
	}

	// Keep the old hash index so old PDFs/QRs still resolve to the immutable
	// old record. Add a new hash index for the newly issued credential.
	newHashDocKey, err := ctx.GetStub().CreateCompositeKey(HashDocCompositeKey, []string{normalizedHash, newDocID})
	if err != nil {
		return fmt.Errorf("failed to create new hash index key: %w", err)
	}
	if err := ctx.GetStub().PutState(newHashDocKey, []byte{0x00}); err != nil {
		return fmt.Errorf("failed to store new hash index: %w", err)
	}

	nextVersion := document.Version + 1
	if nextVersion < 2 {
		nextVersion = 2
	}

	// Mark old document as superseded without changing its anchored data.
	document.Status = StatusReissued
	document.ReissuedToDocID = newDocID
	document.ReissuedTimestamp = txTimestamp
	document.ReissueReason = reason

	oldDocumentJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("failed to marshal old reissued document: %w", err)
	}
	if err := ctx.GetStub().PutState(docID, oldDocumentJSON); err != nil {
		return fmt.Errorf("failed to mark old document as reissued: %w", err)
	}

	newDocument := models.Certificate{
		DocID:             newDocID,
		Hash:              normalizedHash,
		StudentID:         document.StudentID,
		IssuerID:          document.IssuerID,
		Timestamp:         txTimestamp,
		Status:            StatusActive,
		Version:           nextVersion,
		OriginalDocID:     originalDocID,
		PreviousDocID:     docID,
		ReissuedTimestamp: txTimestamp,
		ReissueReason:     reason,
		JsonContent:       newJsonContent,
	}

	documentJSON, err := json.Marshal(newDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal new reissued document: %w", err)
	}
	if err := ctx.GetStub().PutState(newDocID, documentJSON); err != nil {
		return fmt.Errorf("failed to store new reissued document: %w", err)
	}
	if err := ctx.GetStub().SetEvent(EventDocumentReissued, documentJSON); err != nil {
		return fmt.Errorf("failed to emit %s event: %w", EventDocumentReissued, err)
	}
	return nil
}

// GetReissueHistory returns all prior versions of a document stored via
// ReissueDocument composite keys.
func (c *CertificateContract) GetReissueHistory(ctx contractapi.TransactionContextInterface, docID string) ([]*models.ReissueHistoryRecord, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}
	if docID == "" {
		return nil, fmt.Errorf("docID is required")
	}

	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(ReissueHistoryCompositeKey, []string{docID})
	if err != nil {
		return nil, fmt.Errorf("failed to query reissue history: %w", err)
	}
	defer iterator.Close()

	records := make([]*models.ReissueHistoryRecord, 0)
	for iterator.HasNext() {
		kv, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate reissue history: %w", err)
		}

		var record models.ReissueHistoryRecord
		if err := json.Unmarshal(kv.Value, &record); err != nil {
			return nil, fmt.Errorf("failed to unmarshal reissue history record: %w", err)
		}
		records = append(records, &record)
	}
	return records, nil
}

// GetVersionChain returns all linked credential versions for a reissue chain.
// It walks backward to the original document, then forward through
// ReissuedToDocID links so callers can render a full certificate version chain.
func (c *CertificateContract) GetVersionChain(ctx contractapi.TransactionContextInterface, docID string) ([]*models.Certificate, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}
	if docID == "" {
		return nil, fmt.Errorf("docID is required")
	}

	current, err := c.GetDocument(ctx, docID)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for current.PreviousDocID != "" && !seen[current.DocID] {
		seen[current.DocID] = true
		prev, err := c.GetDocument(ctx, current.PreviousDocID)
		if err != nil {
			break
		}
		current = prev
	}

	chain := make([]*models.Certificate, 0)
	seen = map[string]bool{}
	for current != nil && current.DocID != "" && !seen[current.DocID] {
		seen[current.DocID] = true
		chain = append(chain, current)
		if current.ReissuedToDocID == "" {
			break
		}
		next, err := c.GetDocument(ctx, current.ReissuedToDocID)
		if err != nil {
			break
		}
		current = next
	}

	return chain, nil
}

// RegisterDocumentBatch registers multiple documents atomically. Each item is
// processed independently — failures for one item do NOT roll back successes
// for others. The function returns a result array so the caller knows exactly
// which docIDs succeeded or failed.
func (c *CertificateContract) RegisterDocumentBatch(ctx contractapi.TransactionContextInterface, itemsJson string) ([]models.BatchRegistrationResult, error) {
	if err := utils.AuthorizeWithMSP(ctx, registerDocumentRoles); err != nil {
		return nil, err
	}

	var items []models.BatchDocumentItem
	if err := json.Unmarshal([]byte(itemsJson), &items); err != nil {
		return nil, fmt.Errorf("itemsJson must be a valid JSON array: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("items array is empty")
	}
	if len(items) > 500 {
		return nil, fmt.Errorf("batch size exceeds maximum of 500")
	}

	txTimestamp, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]models.BatchRegistrationResult, 0, len(items))
	successDocIDs := make([]string, 0)

	for _, item := range items {
		res := models.BatchRegistrationResult{DocID: item.DocID}

		if item.DocID == "" || item.Hash == "" || item.StudentID == "" {
			res.Success = false
			res.Error = "docID, hash and studentID are required"
			results = append(results, res)
			continue
		}

		normalizedHash, err := normalizeSHA256Hash(item.Hash)
		if err != nil {
			res.Success = false
			res.Error = err.Error()
			results = append(results, res)
			continue
		}

		exists, err := c.documentExists(ctx, item.DocID)
		if err != nil {
			res.Success = false
			res.Error = fmt.Sprintf("read error: %s", err.Error())
			results = append(results, res)
			continue
		}
		if exists {
			res.Success = false
			res.Error = fmt.Sprintf("document %s already exists", item.DocID)
			results = append(results, res)
			continue
		}

		issuerID := item.IssuerID
		if issuerID == "" {
			issuerID, err = utils.GetClientMSPID(ctx)
			if err != nil {
				res.Success = false
				res.Error = fmt.Sprintf("issuerID resolution failed: %s", err.Error())
				results = append(results, res)
				continue
			}
		}

		if item.JsonContent != "" {
			var probe map[string]interface{}
			if err := json.Unmarshal([]byte(item.JsonContent), &probe); err != nil {
				res.Success = false
				res.Error = fmt.Sprintf("jsonContent must be valid JSON: %s", err.Error())
				results = append(results, res)
				continue
			}
		}

		document := models.Certificate{
			DocID:         item.DocID,
			Hash:          normalizedHash,
			StudentID:     item.StudentID,
			IssuerID:      issuerID,
			Timestamp:     txTimestamp,
			Status:        StatusActive,
			Version:       1,
			OriginalDocID: item.DocID,
			JsonContent:   item.JsonContent,
		}

		documentJSON, err := json.Marshal(document)
		if err != nil {
			res.Success = false
			res.Error = fmt.Sprintf("marshal error: %s", err.Error())
			results = append(results, res)
			continue
		}

		if err := ctx.GetStub().PutState(item.DocID, documentJSON); err != nil {
			res.Success = false
			res.Error = fmt.Sprintf("store error: %s", err.Error())
			results = append(results, res)
			continue
		}

		hashDocKey, err := ctx.GetStub().CreateCompositeKey(HashDocCompositeKey, []string{normalizedHash, item.DocID})
		if err != nil {
			res.Success = false
			res.Error = fmt.Sprintf("hash index error: %s", err.Error())
			results = append(results, res)
			continue
		}
		if err := ctx.GetStub().PutState(hashDocKey, []byte{0x00}); err != nil {
			res.Success = false
			res.Error = fmt.Sprintf("hash index store error: %s", err.Error())
			results = append(results, res)
			continue
		}

		res.Success = true
		results = append(results, res)
		successDocIDs = append(successDocIDs, item.DocID)
	}

	// Emit a single batch event with the list of successfully registered docIDs.
	eventPayload, _ := json.Marshal(map[string]interface{}{
		"docIDs":    successDocIDs,
		"count":     len(successDocIDs),
		"timestamp": txTimestamp,
	})
	_ = ctx.GetStub().SetEvent(EventDocumentBatchRegistered, eventPayload)

	return results, nil
}

// SetVerificationTimeWindow sets a global time window (startUnix, endUnix)
// during which credentials may be verified. Outside this window VerifyDocument
// returns an error. Pass 0 for both to disable the restriction.
func (c *CertificateContract) SetVerificationTimeWindow(ctx contractapi.TransactionContextInterface, startUnix int64, endUnix int64) error {
	if err := utils.AuthorizeWithMSP(ctx, revokeDocumentRoles); err != nil {
		return err
	}
	if startUnix < 0 || endUnix < 0 {
		return fmt.Errorf("startUnix and endUnix must be non-negative")
	}
	if endUnix != 0 && endUnix <= startUnix {
		return fmt.Errorf("endUnix must be greater than startUnix")
	}

	window := models.VerificationTimeWindow{StartUnix: startUnix, EndUnix: endUnix}
	windowJSON, err := json.Marshal(window)
	if err != nil {
		return fmt.Errorf("failed to marshal time window: %w", err)
	}
	if err := ctx.GetStub().PutState(GlobalStateKeyVerificationWindow, windowJSON); err != nil {
		return fmt.Errorf("failed to store time window: %w", err)
	}
	return nil
}

// IsWithinVerificationWindow returns true if the current transaction timestamp
// falls inside the configured global verification window, or if no window is set.
func (c *CertificateContract) IsWithinVerificationWindow(ctx contractapi.TransactionContextInterface) (bool, error) {
	window, err := c.getVerificationTimeWindow(ctx)
	if err != nil {
		return false, err
	}
	if window == nil {
		return true, nil
	}
	txTime, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return false, err
	}
	if window.StartUnix > 0 && txTime < window.StartUnix {
		return false, nil
	}
	if window.EndUnix > 0 && txTime > window.EndUnix {
		return false, nil
	}
	return true, nil
}

func (c *CertificateContract) getVerificationTimeWindow(ctx contractapi.TransactionContextInterface) (*models.VerificationTimeWindow, error) {
	windowJSON, err := ctx.GetStub().GetState(GlobalStateKeyVerificationWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to read verification time window: %w", err)
	}
	if windowJSON == nil {
		return nil, nil
	}
	var window models.VerificationTimeWindow
	if err := json.Unmarshal(windowJSON, &window); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verification time window: %w", err)
	}
	return &window, nil
}

func (c *CertificateContract) GetDocument(ctx contractapi.TransactionContextInterface, docID string) (*models.Certificate, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}
	if docID == "" {
		return nil, fmt.Errorf("docID is required")
	}

	documentJSON, err := ctx.GetStub().GetState(docID)
	if err != nil {
		return nil, fmt.Errorf("failed to read document %s: %w", docID, err)
	}
	if documentJSON == nil {
		return nil, fmt.Errorf("document %s does not exist", docID)
	}

	var document models.Certificate
	if err := json.Unmarshal(documentJSON, &document); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document: %w", err)
	}

	return &document, nil
}

func (c *CertificateContract) GetDocumentPrivate(ctx contractapi.TransactionContextInterface, docID string) (*PrivateDocumentResponse, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}
	if docID == "" {
		return nil, fmt.Errorf("docID is required")
	}

	documentJSON, err := ctx.GetStub().GetState(docID)
	if err != nil {
		return nil, fmt.Errorf("failed to read document %s: %w", docID, err)
	}
	if documentJSON == nil {
		return nil, fmt.Errorf("document %s does not exist", docID)
	}

	var document models.Certificate
	if err := json.Unmarshal(documentJSON, &document); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public document: %w", err)
	}

	privateJSON, err := ctx.GetStub().GetPrivateData(PrivateDataCollection, docID)
	if err != nil {
		return nil, fmt.Errorf("failed to read private details for %s: %w", docID, err)
	}

	response := &PrivateDocumentResponse{Document: &document}
	if len(privateJSON) > 0 {
		var privateDetails models.PrivateDocumentDetails
		if err := json.Unmarshal(privateJSON, &privateDetails); err != nil {
			return nil, fmt.Errorf("failed to unmarshal private details: %w", err)
		}
		response.PrivateDetails = &privateDetails
	}

	return response, nil
}

func (c *CertificateContract) GetHistory(ctx contractapi.TransactionContextInterface, docID string) ([]*HistoryRecord, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}
	if docID == "" {
		return nil, fmt.Errorf("docID is required")
	}

	iterator, err := ctx.GetStub().GetHistoryForKey(docID)
	if err != nil {
		return nil, fmt.Errorf("failed to read history for document %s: %w", docID, err)
	}
	defer iterator.Close()

	records := make([]*HistoryRecord, 0)
	for iterator.HasNext() {
		modification, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate history for %s: %w", docID, err)
		}

		record := &HistoryRecord{
			TxID:      modification.TxId,
			Timestamp: time.Unix(modification.Timestamp.Seconds, int64(modification.Timestamp.Nanos)).Unix(),
			IsDelete:  modification.IsDelete,
		}

		if len(modification.Value) > 0 {
			var document models.Certificate
			if err := json.Unmarshal(modification.Value, &document); err != nil {
				return nil, fmt.Errorf("failed to unmarshal history record for %s: %w", docID, err)
			}
			record.Document = &document
		}

		records = append(records, record)
	}

	return records, nil
}

func (c *CertificateContract) GetAllDocuments(ctx contractapi.TransactionContextInterface) ([]*models.Certificate, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}

	iterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to read documents: %w", err)
	}
	defer iterator.Close()

	documents := make([]*models.Certificate, 0)
	for iterator.HasNext() {
		kv, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate documents: %w", err)
		}
		if strings.HasPrefix(kv.Key, "\x00") {
			continue
		}

		var document models.Certificate
		if err := json.Unmarshal(kv.Value, &document); err != nil || document.DocID == "" {
			continue
		}
		documents = append(documents, &document)
	}

	return documents, nil
}

func (c *CertificateContract) DocumentExists(ctx contractapi.TransactionContextInterface, docID string) (bool, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return false, err
	}
	return c.documentExists(ctx, docID)
}

func (c *CertificateContract) documentExists(ctx contractapi.TransactionContextInterface, docID string) (bool, error) {
	documentJSON, err := ctx.GetStub().GetState(docID)
	if err != nil {
		return false, fmt.Errorf("failed to read document %s: %w", docID, err)
	}

	return documentJSON != nil, nil
}

func (c *CertificateContract) VerifyDocumentByDocIDOrHash(ctx contractapi.TransactionContextInterface, identifier string) (*VerificationResponse, error) {
	if err := utils.AuthorizeWithMSP(ctx, readDocumentRoles); err != nil {
		return nil, err
	}
	if identifier == "" {
		return nil, fmt.Errorf("identifier is required")
	}

	resp, err := c.VerifyDocument(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if resp.Exists {
		return resp, nil
	}

	return c.VerifyDocumentByHash(ctx, identifier)
}

func (c *CertificateContract) updatePrivateRevocationReason(ctx contractapi.TransactionContextInterface, docID string, reason string) error {
	privateJSON, err := ctx.GetStub().GetPrivateData(PrivateDataCollection, docID)
	if err != nil {
		return fmt.Errorf("failed to read private details for %s: %w", docID, err)
	}
	if len(privateJSON) == 0 {
		return nil
	}

	var privateDetails models.PrivateDocumentDetails
	if err := json.Unmarshal(privateJSON, &privateDetails); err != nil {
		return fmt.Errorf("failed to unmarshal private details for %s: %w", docID, err)
	}
	privateDetails.RevocationReason = reason

	updatedPrivateJSON, err := json.Marshal(privateDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal private details for %s: %w", docID, err)
	}
	if err := ctx.GetStub().PutPrivateData(PrivateDataCollection, docID, updatedPrivateJSON); err != nil {
		return fmt.Errorf("failed to update private details for %s: %w", docID, err)
	}
	return nil
}

func (c *CertificateContract) getTransactionUnixTimestamp(ctx contractapi.TransactionContextInterface) (int64, error) {
	txTime, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, fmt.Errorf("failed to get tx timestamp: %w", err)
	}
	return txTime.Seconds, nil
}

func normalizeSHA256Hash(hash string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(hash))
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("hash must be a SHA-256 hex string")
	}
	return normalized, nil
}

// Backward-compatible wrappers for existing integrations.
func (c *CertificateContract) IssueCertificate(ctx contractapi.TransactionContextInterface, certID string, hash string) error {
	return c.RegisterDocument(ctx, certID, hash, certID, "")
}

func (c *CertificateContract) RevokeCertificate(ctx contractapi.TransactionContextInterface, certID string) error {
	return c.RevokeDocument(ctx, certID, "revoked by issuer/admin")
}

func (c *CertificateContract) GetCertificate(ctx contractapi.TransactionContextInterface, certID string) (*models.Certificate, error) {
	return c.GetDocument(ctx, certID)
}

func (c *CertificateContract) CertificateExists(ctx contractapi.TransactionContextInterface, certID string) (bool, error) {
	return c.DocumentExists(ctx, certID)
}
