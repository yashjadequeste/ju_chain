package utils

import (
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func GetClientRole(ctx contractapi.TransactionContextInterface) (string, error) {
	role, found, err := ctx.GetClientIdentity().GetAttributeValue("role")
	if err != nil {
		return "", fmt.Errorf("unable to get role attribute: %w", err)
	}
	if !found || role == "" {
		return "", fmt.Errorf("role attribute not found")
	}

	return role, nil
}

func GetClientMSPID(ctx contractapi.TransactionContextInterface) (string, error) {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("unable to get MSP ID: %w", err)
	}
	if mspID == "" {
		return "", fmt.Errorf("MSP ID is empty")
	}

	return mspID, nil
}

func Authorize(ctx contractapi.TransactionContextInterface, allowedRoles []string) error {
	role, err := GetClientRole(ctx)
	if err != nil {
		return err
	}

	for _, allowedRole := range allowedRoles {
		if role == allowedRole {
			return nil
		}
	}

	return fmt.Errorf("access denied for role %s", role)
}

func AuthorizeWithMSP(ctx contractapi.TransactionContextInterface, allowedRoles []string) error {
	if err := Authorize(ctx, allowedRoles); err == nil {
		return nil
	}

	mspID, err := GetClientMSPID(ctx)
	if err != nil {
		return err
	}

	normalizedMSP := normalizeIdentityToken(mspID)
	for _, allowedRole := range allowedRoles {
		normalizedRole := normalizeIdentityToken(allowedRole)
		if normalizedMSP == normalizedRole {
			return nil
		}
	}

	return fmt.Errorf("access denied for MSP %s", mspID)
}

func normalizeIdentityToken(value string) string {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	replacer := strings.NewReplacer("_", "", "-", "", " ", "")
	normalized = replacer.Replace(normalized)
	normalized = strings.TrimSuffix(normalized, "MSP")
	normalized = strings.TrimSuffix(normalized, "ORG")
	return normalized
}
