#!/usr/bin/env bash

set -euo pipefail

# Negative RBAC tests:
# 1) ISSUER cannot revoke
# 2) identity without role cannot read

NETWORK_DIR="${NETWORK_DIR:-/home/jatin/Justify/justify/fabric-samples/test-network}"
CC_NAME="${CC_NAME:-justifai_cert}"
CHANNEL="${CHANNEL:-mychannel}"
CERT_ID="${1:-cert-rbac-neg-$(date +%s)}"
CERT_HASH="${2:-hash-rbac-neg-001}"

ADMIN_MSP_PATH="${ADMIN_MSP_PATH:-$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/uniadmin2@org1.example.com/msp}"
ISSUER_MSP_PATH="${ISSUER_MSP_PATH:-$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/issuer1@org1.example.com/msp}"
NOROLE_MSP_PATH="${NOROLE_MSP_PATH:-$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp}"

export PATH="/home/jatin/Justify/justify/fabric-samples/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export FABRIC_CFG_PATH="/home/jatin/Justify/justify/fabric-samples/config"

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"

ORDERER_CA="$NETWORK_DIR/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"
PEER0_ORG1_CA="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"
PEER0_ORG2_CA="$NETWORK_DIR/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem"

if [[ ! -d "$ADMIN_MSP_PATH" ]]; then
  echo "FAIL: Admin MSP path not found: $ADMIN_MSP_PATH"
  exit 1
fi

if [[ ! -d "$ISSUER_MSP_PATH" ]]; then
  echo "FAIL: Issuer MSP path not found: $ISSUER_MSP_PATH"
  echo "Hint: register/enroll issuer identity first (role=ISSUER:ecert)."
  exit 1
fi

if [[ ! -d "$NOROLE_MSP_PATH" ]]; then
  echo "FAIL: No-role MSP path not found: $NOROLE_MSP_PATH"
  exit 1
fi

echo "==> Setup: issue certificate with UNIVERSITY_ADMIN identity"
CORE_PEER_MSPCONFIGPATH="$ADMIN_MSP_PATH" \
peer chaincode invoke -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" \
  -C "$CHANNEL" -n "$CC_NAME" \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
  --waitForEvent \
  -c "{\"Args\":[\"IssueCertificate\",\"${CERT_ID}\",\"${CERT_HASH}\"]}" >/dev/null

echo "==> Test 1: ISSUER should be denied RevokeCertificate"
set +e
CORE_PEER_MSPCONFIGPATH="$ISSUER_MSP_PATH" \
peer chaincode invoke -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" \
  -C "$CHANNEL" -n "$CC_NAME" \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
  --waitForEvent \
  -c "{\"Args\":[\"RevokeCertificate\",\"${CERT_ID}\"]}" 2>&1 | tee /tmp/rbac_neg_issuer.log
issuer_rc=$?
set -e

if [[ $issuer_rc -eq 0 ]]; then
  echo "FAIL: ISSUER revoke unexpectedly succeeded."
  exit 1
fi

if ! grep -q "access denied" /tmp/rbac_neg_issuer.log; then
  echo "FAIL: Expected 'access denied' in issuer revoke failure."
  exit 1
fi
echo "PASS: ISSUER revoke denied."

echo "==> Test 2: Identity without role should be denied GetCertificate"
set +e
CORE_PEER_MSPCONFIGPATH="$NOROLE_MSP_PATH" \
peer chaincode query -C "$CHANNEL" -n "$CC_NAME" \
  -c "{\"Args\":[\"GetCertificate\",\"${CERT_ID}\"]}" 2>&1 | tee /tmp/rbac_neg_norole.log
norole_rc=$?
set -e

if [[ $norole_rc -eq 0 ]]; then
  echo "FAIL: No-role identity read unexpectedly succeeded."
  exit 1
fi

if ! grep -q "role attribute not found" /tmp/rbac_neg_norole.log; then
  echo "FAIL: Expected 'role attribute not found' in no-role read failure."
  exit 1
fi
echo "PASS: Missing role denied."

echo
echo "RBAC negative tests complete."
