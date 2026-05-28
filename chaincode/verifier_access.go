package chaincode

import (
	"encoding/json"
	"fmt"
	"strings"

	"justifai_chaincode/models"
	"justifai_chaincode/utils"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	tenantSettingsKeyPrefix      = "TENANT~SETTINGS~"
	verifierAccessKeyPrefix      = "VERIFIER~ACCESS~"
	verifierGrantKeyPrefix       = "VERIFIER~GRANT~"
	tenantAccessCompositeKey     = "tenantAccess"
	verifierAccessStatusPending  = "PENDING"
	verifierAccessStatusApproved = "APPROVED"
	verifierAccessStatusDeclined = "DECLINED"
)

var (
	tenantSettingsWriteRoles = []string{"ADMIN_ORG", "UNIVERSITY_ADMIN", "ORG1", "ISSUER_ORG"}
	verifierAccessWriteRoles = []string{"ADMIN_ORG", "UNIVERSITY_ADMIN", "ORG1", "VERIFIER_ORG", "VERIFIER"}
	verifierAccessReadRoles  = []string{"ADMIN_ORG", "UNIVERSITY_ADMIN", "ORG1", "VERIFIER_ORG", "VERIFIER", "ISSUER_ORG"}
)

func tenantSettingsKey(tenantID string) string {
	return tenantSettingsKeyPrefix + strings.TrimSpace(tenantID)
}

func verifierAccessKey(verifierID, credentialID string, requestedAt int64) string {
	return fmt.Sprintf("%s%s~%s~%d",
		verifierAccessKeyPrefix,
		strings.TrimSpace(verifierID),
		strings.TrimSpace(credentialID),
		requestedAt,
	)
}

func verifierAccessPairPrefix(verifierID, credentialID string) string {
	return verifierAccessKeyPrefix + strings.TrimSpace(verifierID) + "~" + strings.TrimSpace(credentialID) + "~"
}

func verifierGrantKey(verifierID, credentialID string) string {
	return verifierGrantKeyPrefix + strings.TrimSpace(verifierID) + "~" + strings.TrimSpace(credentialID)
}

func parseBoolString(value string) (bool, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("requireApproval must be true or false")
	}
}

// SetTenantVerificationSettings stores per-institute verifier approval policy on the ledger.
func (c *CertificateContract) SetTenantVerificationSettings(ctx contractapi.TransactionContextInterface, tenantID string, requireApproval string, updatedBy string) error {
	if err := utils.AuthorizeWithMSP(ctx, tenantSettingsWriteRoles); err != nil {
		return err
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenantID is required")
	}
	require, err := parseBoolString(requireApproval)
	if err != nil {
		return err
	}
	ts, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return err
	}
	settings := models.TenantVerificationSettings{
		TenantID:                      tenantID,
		RequireVerifierAccessApproval: require,
		UpdatedAt:                     ts,
		UpdatedBy:                     strings.TrimSpace(updatedBy),
	}
	payload, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(tenantSettingsKey(tenantID), payload)
}

// GetTenantVerificationSettings reads institute verifier approval policy from the ledger.
func (c *CertificateContract) GetTenantVerificationSettings(ctx contractapi.TransactionContextInterface, tenantID string) (*models.TenantVerificationSettings, error) {
	if err := utils.AuthorizeWithMSP(ctx, verifierAccessReadRoles); err != nil {
		return nil, err
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenantID is required")
	}
	raw, err := ctx.GetStub().GetState(tenantSettingsKey(tenantID))
	if err != nil {
		return nil, err
	}
	if raw == nil || len(raw) == 0 {
		return &models.TenantVerificationSettings{
			TenantID:                      tenantID,
			RequireVerifierAccessApproval: false,
		}, nil
	}
	var settings models.TenantVerificationSettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	return &settings, nil
}

func (c *CertificateContract) getVerifierAccessRequestAt(
	ctx contractapi.TransactionContextInterface,
	verifierID, credentialID string,
	requestedAt int64,
) (*models.VerifierAccessRequest, error) {
	raw, err := ctx.GetStub().GetState(verifierAccessKey(verifierID, credentialID, requestedAt))
	if err != nil {
		return nil, err
	}
	if raw == nil || len(raw) == 0 {
		return nil, nil
	}
	var rec models.VerifierAccessRequest
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (c *CertificateContract) putVerifierAccessRequest(ctx contractapi.TransactionContextInterface, rec *models.VerifierAccessRequest) error {
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	mainKey := verifierAccessKey(rec.VerifierID, rec.CredentialID, rec.RequestedAt)
	if err := ctx.GetStub().PutState(mainKey, payload); err != nil {
		return err
	}
	indexKey, err := ctx.GetStub().CreateCompositeKey(
		tenantAccessCompositeKey,
		[]string{
			rec.TenantID,
			rec.Status,
			fmt.Sprintf("%020d", rec.RequestedAt),
			rec.VerifierID,
			rec.CredentialID,
		},
	)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(indexKey, []byte(mainKey))
}

func (c *CertificateContract) setVerifierGrantApproved(ctx contractapi.TransactionContextInterface, verifierID, credentialID string) error {
	return ctx.GetStub().PutState(verifierGrantKey(verifierID, credentialID), []byte(verifierAccessStatusApproved))
}

func (c *CertificateContract) hasVerifierGrantApproved(ctx contractapi.TransactionContextInterface, verifierID, credentialID string) (bool, error) {
	raw, err := ctx.GetStub().GetState(verifierGrantKey(verifierID, credentialID))
	if err != nil {
		return false, err
	}
	return raw != nil && string(raw) == verifierAccessStatusApproved, nil
}

func (c *CertificateContract) listVerifierAccessForPair(
	ctx contractapi.TransactionContextInterface,
	verifierID, credentialID string,
) ([]*models.VerifierAccessRequest, error) {
	prefix := verifierAccessPairPrefix(verifierID, credentialID)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"\uffff")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*models.VerifierAccessRequest
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if kv.Value == nil {
			continue
		}
		var rec models.VerifierAccessRequest
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			continue
		}
		out = append(out, &rec)
	}
	return out, nil
}

func (c *CertificateContract) findOpenPendingRequest(
	ctx contractapi.TransactionContextInterface,
	verifierID, credentialID string,
) (*models.VerifierAccessRequest, error) {
	all, err := c.listVerifierAccessForPair(ctx, verifierID, credentialID)
	if err != nil {
		return nil, err
	}
	var latest *models.VerifierAccessRequest
	for _, rec := range all {
		if rec.Status != verifierAccessStatusPending {
			continue
		}
		if latest == nil || rec.RequestedAt > latest.RequestedAt {
			latest = rec
		}
	}
	return latest, nil
}

func (c *CertificateContract) findLatestApprovedRequest(
	ctx contractapi.TransactionContextInterface,
	verifierID, credentialID string,
) (*models.VerifierAccessRequest, error) {
	all, err := c.listVerifierAccessForPair(ctx, verifierID, credentialID)
	if err != nil {
		return nil, err
	}
	var latest *models.VerifierAccessRequest
	for _, rec := range all {
		if rec.Status != verifierAccessStatusApproved {
			continue
		}
		if latest == nil || rec.RequestedAt > latest.RequestedAt {
			latest = rec
		}
	}
	return latest, nil
}

// SubmitVerifierAccessRequest creates or refreshes a pending verifier access grant request.
func (c *CertificateContract) SubmitVerifierAccessRequest(
	ctx contractapi.TransactionContextInterface,
	verifierID string,
	credentialID string,
	tenantID string,
	source string,
	verifierEmail string,
	verifierName string,
	verifierMobile string,
) (*models.VerifierAccessRequest, error) {
	if err := utils.AuthorizeWithMSP(ctx, verifierAccessWriteRoles); err != nil {
		return nil, err
	}
	verifierID = strings.TrimSpace(verifierID)
	credentialID = strings.TrimSpace(credentialID)
	tenantID = strings.TrimSpace(tenantID)
	source = strings.ToUpper(strings.TrimSpace(source))
	verifierEmail = strings.TrimSpace(verifierEmail)
	verifierName = strings.TrimSpace(verifierName)
	verifierMobile = strings.TrimSpace(verifierMobile)
	if verifierID == "" || credentialID == "" || tenantID == "" {
		return nil, fmt.Errorf("verifierID, credentialID and tenantID are required")
	}
	if source == "" {
		source = "MANUAL"
	}

	approved, err := c.hasVerifierGrantApproved(ctx, verifierID, credentialID)
	if err != nil {
		return nil, err
	}
	if approved {
		existing, err := c.findLatestApprovedRequest(ctx, verifierID, credentialID)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return existing, nil
		}
	}

	openPending, err := c.findOpenPendingRequest(ctx, verifierID, credentialID)
	if err != nil {
		return nil, err
	}
	if openPending != nil {
		return openPending, nil
	}

	ts, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return nil, err
	}
	rec := &models.VerifierAccessRequest{
		VerifierID:     verifierID,
		CredentialID:   credentialID,
		TenantID:       tenantID,
		Status:         verifierAccessStatusPending,
		Source:         source,
		VerifierEmail:  verifierEmail,
		VerifierName:   verifierName,
		VerifierMobile: verifierMobile,
		RequestedAt:    ts,
		DecidedBy:      "",
		DeclineReason:  "",
		DecidedAt:      0,
	}
	if err := c.putVerifierAccessRequest(ctx, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// DecideVerifierAccessRequest approves or declines a specific verifier access request.
// requestedAt is the unix timestamp from the request row (third segment of the API id).
func (c *CertificateContract) DecideVerifierAccessRequest(
	ctx contractapi.TransactionContextInterface,
	verifierID string,
	credentialID string,
	requestedAt string,
	decision string,
	decidedBy string,
	reason string,
) (*models.VerifierAccessRequest, error) {
	if err := utils.AuthorizeWithMSP(ctx, tenantSettingsWriteRoles); err != nil {
		return nil, err
	}
	verifierID = strings.TrimSpace(verifierID)
	credentialID = strings.TrimSpace(credentialID)
	requestedAt = strings.TrimSpace(requestedAt)
	decision = strings.ToUpper(strings.TrimSpace(decision))
	decidedBy = strings.TrimSpace(decidedBy)
	reason = strings.TrimSpace(reason)
	if verifierID == "" || credentialID == "" || requestedAt == "" {
		return nil, fmt.Errorf("verifierID, credentialID and requestedAt are required")
	}
	if decision != verifierAccessStatusApproved && decision != verifierAccessStatusDeclined {
		return nil, fmt.Errorf("decision must be APPROVED or DECLINED")
	}

	reqAt, err := parseInt64String(requestedAt)
	if err != nil {
		return nil, fmt.Errorf("requestedAt must be a unix timestamp: %w", err)
	}

	existing, err := c.getVerifierAccessRequestAt(ctx, verifierID, credentialID, reqAt)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("access request not found")
	}
	if existing.Status != verifierAccessStatusPending {
		return nil, fmt.Errorf("request is already %s", existing.Status)
	}

	ts, err := c.getTransactionUnixTimestamp(ctx)
	if err != nil {
		return nil, err
	}
	existing.Status = decision
	existing.DecidedBy = decidedBy
	existing.DecidedAt = ts
	if decision == verifierAccessStatusDeclined {
		existing.DeclineReason = reason
	} else {
		existing.DeclineReason = ""
		if err := c.setVerifierGrantApproved(ctx, verifierID, credentialID); err != nil {
			return nil, err
		}
	}
	if err := c.putVerifierAccessRequest(ctx, existing); err != nil {
		return nil, err
	}
	return existing, nil
}

func parseInt64String(value string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(value, "%d", &n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// GetVerifierAccessGrant returns the effective access state for a verifier/credential pair.
// Priority: APPROVED grant → open PENDING → latest DECLINED.
func (c *CertificateContract) GetVerifierAccessGrant(ctx contractapi.TransactionContextInterface, verifierID string, credentialID string) (*models.VerifierAccessRequest, error) {
	if err := utils.AuthorizeWithMSP(ctx, verifierAccessReadRoles); err != nil {
		return nil, err
	}
	verifierID = strings.TrimSpace(verifierID)
	credentialID = strings.TrimSpace(credentialID)
	if verifierID == "" || credentialID == "" {
		return nil, fmt.Errorf("verifierID and credentialID are required")
	}

	approved, err := c.hasVerifierGrantApproved(ctx, verifierID, credentialID)
	if err != nil {
		return nil, err
	}
	if approved {
		rec, err := c.findLatestApprovedRequest(ctx, verifierID, credentialID)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			return rec, nil
		}
	}

	pending, err := c.findOpenPendingRequest(ctx, verifierID, credentialID)
	if err != nil {
		return nil, err
	}
	if pending != nil {
		return pending, nil
	}

	all, err := c.listVerifierAccessForPair(ctx, verifierID, credentialID)
	if err != nil {
		return nil, err
	}
	var latest *models.VerifierAccessRequest
	for _, rec := range all {
		if latest == nil || rec.RequestedAt > latest.RequestedAt {
			latest = rec
		}
	}
	return latest, nil
}

// HasApprovedVerifierAccess evaluates whether access is granted.
func (c *CertificateContract) HasApprovedVerifierAccess(ctx contractapi.TransactionContextInterface, verifierID string, credentialID string) (bool, error) {
	return c.hasVerifierGrantApproved(ctx, verifierID, credentialID)
}

// ListVerifierAccessByTenant returns access requests for an institute (optional status filter).
func (c *CertificateContract) ListVerifierAccessByTenant(ctx contractapi.TransactionContextInterface, tenantID string, statusFilter string) ([]*models.VerifierAccessRequest, error) {
	if err := utils.AuthorizeWithMSP(ctx, verifierAccessReadRoles); err != nil {
		return nil, err
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenantID is required")
	}
	statusFilter = strings.ToUpper(strings.TrimSpace(statusFilter))

	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(tenantAccessCompositeKey, []string{tenantID})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*models.VerifierAccessRequest
	seen := map[string]bool{}
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if kv.Value == nil {
			continue
		}
		mainKey := string(kv.Value)
		if seen[mainKey] {
			continue
		}
		seen[mainKey] = true
		raw, err := ctx.GetStub().GetState(mainKey)
		if err != nil || raw == nil {
			continue
		}
		var rec models.VerifierAccessRequest
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue
		}
		if statusFilter != "" && rec.Status != statusFilter {
			continue
		}
		out = append(out, &rec)
	}
	return out, nil
}

// ListVerifierAccessByVerifier returns all access requests created by a verifier.
func (c *CertificateContract) ListVerifierAccessByVerifier(ctx contractapi.TransactionContextInterface, verifierID string) ([]*models.VerifierAccessRequest, error) {
	if err := utils.AuthorizeWithMSP(ctx, verifierAccessReadRoles); err != nil {
		return nil, err
	}
	verifierID = strings.TrimSpace(verifierID)
	if verifierID == "" {
		return nil, fmt.Errorf("verifierID is required")
	}
	prefix := verifierAccessKeyPrefix + verifierID + "~"
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"\uffff")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*models.VerifierAccessRequest
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if kv.Value == nil {
			continue
		}
		var rec models.VerifierAccessRequest
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			continue
		}
		out = append(out, &rec)
	}
	return out, nil
}

// CountVerifierAccessByTenant returns pending (or filtered) count for dashboard badges.
func (c *CertificateContract) CountVerifierAccessByTenant(ctx contractapi.TransactionContextInterface, tenantID string, statusFilter string) (int, error) {
	list, err := c.ListVerifierAccessByTenant(ctx, tenantID, statusFilter)
	if err != nil {
		return 0, err
	}
	return len(list), nil
}

// RequireVerifierAccessApprovalForTenant is a convenience evaluate for backends.
func (c *CertificateContract) RequireVerifierAccessApprovalForTenant(ctx contractapi.TransactionContextInterface, tenantID string) (bool, error) {
	settings, err := c.GetTenantVerificationSettings(ctx, tenantID)
	if err != nil {
		return false, err
	}
	if settings == nil {
		return false, nil
	}
	return settings.RequireVerifierAccessApproval, nil
}
