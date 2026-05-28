package utils

import (
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

type testTransactionContext struct {
	stub     shim.ChaincodeStubInterface
	clientID cid.ClientIdentity
}

func (t *testTransactionContext) GetStub() shim.ChaincodeStubInterface {
	return t.stub
}

func (t *testTransactionContext) GetClientIdentity() cid.ClientIdentity {
	return t.clientID
}

func (t *testTransactionContext) SetStub(stub shim.ChaincodeStubInterface) {
	t.stub = stub
}

func (t *testTransactionContext) SetClientIdentity(clientIdentity cid.ClientIdentity) {
	t.clientID = clientIdentity
}

type fakeClientIdentity struct {
	role      string
	mspID     string
	roleFound bool
}

func (f *fakeClientIdentity) GetID() (string, error) {
	return "test-user", nil
}

func (f *fakeClientIdentity) GetMSPID() (string, error) {
	return f.mspID, nil
}

func (f *fakeClientIdentity) GetAttributeValue(attrName string) (string, bool, error) {
	if attrName != "role" {
		return "", false, nil
	}
	return f.role, f.roleFound, nil
}

func (f *fakeClientIdentity) AssertAttributeValue(attrName string, attrValue string) error {
	v, found, _ := f.GetAttributeValue(attrName)
	if !found || v != attrValue {
		return fmt.Errorf("attribute %s mismatch", attrName)
	}
	return nil
}

func (f *fakeClientIdentity) GetX509Certificate() (*x509.Certificate, error) {
	return nil, nil
}

func TestAuthorize_AllowsExpectedRole(t *testing.T) {
	ctx := &testTransactionContext{
		clientID: &fakeClientIdentity{
			role:      "ISSUER",
			roleFound: true,
		},
	}

	err := Authorize(ctx, []string{"UNIVERSITY_ADMIN", "ISSUER"})
	if err != nil {
		t.Fatalf("expected role to be authorized, got error: %v", err)
	}
}

func TestAuthorize_DeniesUnexpectedRole(t *testing.T) {
	ctx := &testTransactionContext{
		clientID: &fakeClientIdentity{
			role:      "STUDENT",
			roleFound: true,
		},
	}

	err := Authorize(ctx, []string{"UNIVERSITY_ADMIN", "ISSUER"})
	if err == nil {
		t.Fatal("expected authorization to fail for STUDENT role")
	}
}

func TestAuthorize_DeniesMissingRoleAttribute(t *testing.T) {
	ctx := &testTransactionContext{
		clientID: &fakeClientIdentity{
			role:      "",
			roleFound: false,
		},
	}

	err := Authorize(ctx, []string{"UNIVERSITY_ADMIN", "ISSUER"})
	if err == nil {
		t.Fatal("expected authorization to fail when role attribute is missing")
	}
}

func TestAuthorizeWithMSP_AllowsWhenRoleMissingButMSPMatches(t *testing.T) {
	ctx := &testTransactionContext{
		clientID: &fakeClientIdentity{
			role:      "",
			roleFound: false,
			mspID:     "VerifierMSP",
		},
	}

	err := AuthorizeWithMSP(ctx, []string{"VERIFIER_ORG"})
	if err != nil {
		t.Fatalf("expected MSP-based authorization to pass, got: %v", err)
	}
}

func TestAuthorizeWithMSP_DeniesWhenRoleAndMSPMismatch(t *testing.T) {
	ctx := &testTransactionContext{
		clientID: &fakeClientIdentity{
			role:      "STUDENT",
			roleFound: true,
			mspID:     "StudentMSP",
		},
	}

	err := AuthorizeWithMSP(ctx, []string{"VERIFIER_ORG"})
	if err == nil {
		t.Fatal("expected MSP-based authorization to fail")
	}
}

func TestAuthorizeWithMSP_DoesNotAllowSubstringMSPMatch(t *testing.T) {
	ctx := &testTransactionContext{
		clientID: &fakeClientIdentity{
			role:      "",
			roleFound: false,
			mspID:     "BadVerifierMSP",
		},
	}

	err := AuthorizeWithMSP(ctx, []string{"VERIFIER_ORG"})
	if err == nil {
		t.Fatal("expected substring MSP match to be denied")
	}
}
