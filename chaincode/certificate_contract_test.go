package chaincode

import (
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-protos-go/peer"
)

const (
	testHash1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHash2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testHash3 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
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

type mockChaincode struct{}

func (m *mockChaincode) Init(shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

func (m *mockChaincode) Invoke(shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

func runInTx(stub *shimtest.MockStub, txID string, fn func()) {
	stub.MockTransactionStart(txID)
	defer stub.MockTransactionEnd(txID)
	fn()
}

func TestIssueCertificate_RequiresAllowedRole(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	ctx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "STUDENT",
			roleFound: true,
			mspID:     "StudentMSP",
		},
	}

	var err error
	runInTx(stub, "tx-1", func() {
		err = contract.IssueCertificate(ctx, "cert-1", testHash1)
	})
	if err == nil {
		t.Fatal("expected STUDENT role to be denied for IssueCertificate")
	}
}

func TestIssueGetRevokeCertificate_Flow(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})

	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}
	publicRoleCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "VERIFIER",
			roleFound: true,
			mspID:     "VerifierMSP",
		},
	}

	runInTx(stub, "tx-2", func() {
		if err := contract.IssueCertificate(adminCtx, "cert-2", testHash1); err != nil {
			t.Fatalf("issue failed: %v", err)
		}
	})

	cert, err := contract.GetCertificate(publicRoleCtx, "cert-2")
	if err != nil {
		t.Fatalf("get failed for authenticated role: %v", err)
	}
	if cert.Status != StatusActive {
		t.Fatalf("expected status %s, got %s", StatusActive, cert.Status)
	}
	if cert.IssuerID != "UniversityMSP" {
		t.Fatalf("expected issuerID UniversityMSP, got %s", cert.IssuerID)
	}

	runInTx(stub, "tx-3", func() {
		if err := contract.RevokeCertificate(adminCtx, "cert-2"); err != nil {
			t.Fatalf("revoke failed: %v", err)
		}
	})

	revoked, err := contract.GetCertificate(publicRoleCtx, "cert-2")
	if err != nil {
		t.Fatalf("get after revoke failed: %v", err)
	}
	if revoked.Status != StatusRevoked {
		t.Fatalf("expected status %s, got %s", StatusRevoked, revoked.Status)
	}
}

func TestRevokeCertificate_DeniesNonAdmin(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})

	issuerCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "ISSUER",
			roleFound: true,
			mspID:     "IssuerMSP",
		},
	}
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	runInTx(stub, "tx-4", func() {
		if err := contract.IssueCertificate(adminCtx, "cert-3", testHash2); err != nil {
			t.Fatalf("setup issue failed: %v", err)
		}
	})

	var err error
	runInTx(stub, "tx-5", func() {
		err = contract.RevokeCertificate(issuerCtx, "cert-3")
	})
	if err == nil {
		t.Fatal("expected ISSUER role to be denied for RevokeCertificate")
	}
}

func TestVerifyDocumentByHash_AndDocIDOrHash(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})

	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	readCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "VERIFIER",
			roleFound: true,
			mspID:     "VerifierMSP",
		},
	}

	runInTx(stub, "tx-6", func() {
		if err := contract.RegisterDocument(adminCtx, "doc-1", testHash3, "S001", "IssuerMSP"); err != nil {
			t.Fatalf("register failed: %v", err)
		}
	})

	byHash, err := contract.VerifyDocumentByHash(readCtx, testHash3)
	if err != nil {
		t.Fatalf("verify by hash failed: %v", err)
	}
	if !byHash.Exists || byHash.Document == nil || byHash.Document.DocID != "doc-1" {
		t.Fatalf("expected existing document for hash, got %+v", byHash)
	}

	byIdentifier, err := contract.VerifyDocumentByDocIDOrHash(readCtx, testHash3)
	if err != nil {
		t.Fatalf("verify by identifier (hash) failed: %v", err)
	}
	if !byIdentifier.Exists || byIdentifier.Document == nil || byIdentifier.Document.DocID != "doc-1" {
		t.Fatalf("expected existing document for identifier hash, got %+v", byIdentifier)
	}
}

func TestRegisterDocument_RejectsInvalidHash(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	var err error
	runInTx(stub, "tx-7", func() {
		err = contract.RegisterDocument(adminCtx, "doc-invalid", "not-a-sha256", "S001", "IssuerMSP")
	})
	if err == nil {
		t.Fatal("expected invalid hash to be rejected")
	}
}

func TestDocumentExists_RequiresReadAuthorization(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	studentCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "STUDENT",
			roleFound: true,
			mspID:     "StudentMSP",
		},
	}

	if _, err := contract.DocumentExists(studentCtx, "doc-1"); err == nil {
		t.Fatal("expected unauthorized DocumentExists call to fail")
	}
}

func TestRevokeDocument_PreservesIssuedTimestamp(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	runInTx(stub, "tx-8", func() {
		if err := contract.RegisterDocument(adminCtx, "doc-revoke", testHash1, "S001", "IssuerMSP"); err != nil {
			t.Fatalf("register failed: %v", err)
		}
	})
	issued, err := contract.GetDocument(adminCtx, "doc-revoke")
	if err != nil {
		t.Fatalf("get after register failed: %v", err)
	}

	runInTx(stub, "tx-9", func() {
		if err := contract.RevokeDocument(adminCtx, "doc-revoke", "incorrect data"); err != nil {
			t.Fatalf("revoke failed: %v", err)
		}
	})
	revoked, err := contract.GetDocument(adminCtx, "doc-revoke")
	if err != nil {
		t.Fatalf("get after revoke failed: %v", err)
	}
	if revoked.Timestamp != issued.Timestamp {
		t.Fatalf("expected issue timestamp to be preserved, got %d want %d", revoked.Timestamp, issued.Timestamp)
	}
	if revoked.RevokedTimestamp == 0 {
		t.Fatal("expected revoked timestamp to be recorded")
	}
}

func TestGetAllDocuments_ReturnsStoredDocuments(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	runInTx(stub, "tx-10", func() {
		if err := contract.RegisterDocument(adminCtx, "doc-list", testHash2, "S002", "IssuerMSP"); err != nil {
			t.Fatalf("register failed: %v", err)
		}
	})

	documents, err := contract.GetAllDocuments(adminCtx)
	if err != nil {
		t.Fatalf("get all failed: %v", err)
	}
	if len(documents) != 1 || documents[0].DocID != "doc-list" {
		t.Fatalf("expected one listed document, got %+v", documents)
	}
}

func TestRegisterDocumentWithContent_PersistsSubjectOnChain(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	subject := `{"Name":"STUDENT 1 GALAXY","Programme":"B.Tech","Tot1":"75"}`
	runInTx(stub, "tx-11", func() {
		if err := contract.RegisterDocumentWithContent(adminCtx, "doc-content", testHash1, "S003", "IssuerMSP", subject); err != nil {
			t.Fatalf("register with content failed: %v", err)
		}
	})

	stored, err := contract.GetDocument(adminCtx, "doc-content")
	if err != nil {
		t.Fatalf("get after register failed: %v", err)
	}
	if stored.JsonContent != subject {
		t.Fatalf("expected JsonContent to be persisted on chain, got %q", stored.JsonContent)
	}
}

func TestRegisterDocumentWithContent_RejectsInvalidJSON(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	var err error
	runInTx(stub, "tx-12", func() {
		err = contract.RegisterDocumentWithContent(adminCtx, "doc-bad", testHash2, "S004", "IssuerMSP", "{not-json")
	})
	if err == nil {
		t.Fatal("expected invalid JSON content to be rejected")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Freeze / Unfreeze
// ─────────────────────────────────────────────────────────────────────────────

func TestFreezeAndUnfreeze_HappyPath(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	runInTx(stub, "tx-freeze-1", func() {
		if err := contract.RegisterDocument(adminCtx, "doc-freeze", testHash1, "S010", "IssuerMSP"); err != nil {
			t.Fatalf("register failed: %v", err)
		}
	})

	runInTx(stub, "tx-freeze-2", func() {
		if err := contract.FreezeDocument(adminCtx, "doc-freeze", "investigation"); err != nil {
			t.Fatalf("freeze failed: %v", err)
		}
	})
	doc, err := contract.GetDocument(adminCtx, "doc-freeze")
	if err != nil {
		t.Fatalf("get after freeze failed: %v", err)
	}
	if doc.Status != StatusFrozen {
		t.Fatalf("expected status %s, got %s", StatusFrozen, doc.Status)
	}
	if doc.FreezeReason != "investigation" {
		t.Fatalf("expected freeze reason 'investigation', got %q", doc.FreezeReason)
	}
	if doc.FrozenTimestamp == 0 {
		t.Fatal("expected frozen timestamp to be set")
	}

	runInTx(stub, "tx-freeze-3", func() {
		if err := contract.UnfreezeDocument(adminCtx, "doc-freeze", "cleared"); err != nil {
			t.Fatalf("unfreeze failed: %v", err)
		}
	})
	doc, err = contract.GetDocument(adminCtx, "doc-freeze")
	if err != nil {
		t.Fatalf("get after unfreeze failed: %v", err)
	}
	if doc.Status != StatusActive {
		t.Fatalf("expected status %s after unfreeze, got %s", StatusActive, doc.Status)
	}
	if doc.UnfrozenTimestamp == 0 {
		t.Fatal("expected unfrozen timestamp to be set")
	}
}

func TestFreeze_RequiresReason(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	runInTx(stub, "tx-freeze-noreason-1", func() {
		if err := contract.RegisterDocument(adminCtx, "doc-noreason", testHash2, "S011", "IssuerMSP"); err != nil {
			t.Fatalf("register failed: %v", err)
		}
	})

	var err error
	runInTx(stub, "tx-freeze-noreason-2", func() {
		err = contract.FreezeDocument(adminCtx, "doc-noreason", "")
	})
	if err == nil {
		t.Fatal("expected empty reason to be rejected")
	}
}

func TestFreeze_RejectsRevoked(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	runInTx(stub, "tx-freeze-rev-1", func() {
		if err := contract.RegisterDocument(adminCtx, "doc-rev-then-freeze", testHash3, "S012", "IssuerMSP"); err != nil {
			t.Fatalf("register failed: %v", err)
		}
	})
	runInTx(stub, "tx-freeze-rev-2", func() {
		if err := contract.RevokeDocument(adminCtx, "doc-rev-then-freeze", "policy"); err != nil {
			t.Fatalf("revoke failed: %v", err)
		}
	})

	var err error
	runInTx(stub, "tx-freeze-rev-3", func() {
		err = contract.FreezeDocument(adminCtx, "doc-rev-then-freeze", "later")
	})
	if err == nil {
		t.Fatal("expected freeze on revoked document to be rejected")
	}
}

func TestRevoke_BlockedWhenFrozen(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	runInTx(stub, "tx-rb-1", func() {
		if err := contract.RegisterDocument(adminCtx, "doc-rb", testHash1, "S013", "IssuerMSP"); err != nil {
			t.Fatalf("register failed: %v", err)
		}
	})
	runInTx(stub, "tx-rb-2", func() {
		if err := contract.FreezeDocument(adminCtx, "doc-rb", "review"); err != nil {
			t.Fatalf("freeze failed: %v", err)
		}
	})

	var err error
	runInTx(stub, "tx-rb-3", func() {
		err = contract.RevokeDocument(adminCtx, "doc-rb", "policy")
	})
	if err == nil {
		t.Fatal("expected revoke on frozen document to be rejected")
	}
}

func TestUnfreeze_RejectsActive(t *testing.T) {
	contract := &CertificateContract{}
	stub := shimtest.NewMockStub("cert", &mockChaincode{})
	adminCtx := &testTransactionContext{
		stub: stub,
		clientID: &fakeClientIdentity{
			role:      "UNIVERSITY_ADMIN",
			roleFound: true,
			mspID:     "UniversityMSP",
		},
	}

	runInTx(stub, "tx-uf-1", func() {
		if err := contract.RegisterDocument(adminCtx, "doc-uf", testHash2, "S014", "IssuerMSP"); err != nil {
			t.Fatalf("register failed: %v", err)
		}
	})

	var err error
	runInTx(stub, "tx-uf-2", func() {
		err = contract.UnfreezeDocument(adminCtx, "doc-uf", "")
	})
	if err == nil {
		t.Fatal("expected unfreeze on ACTIVE document to be rejected")
	}
}

// NOTE: shimtest.MockStub does not implement GetHistoryForKey, so we cannot
// exercise GetHistory end-to-end here. The contract delegates directly to the
// shim API; integration coverage lives in the deployed test-network.
