#!/usr/bin/env bash

set -euo pipefail

# Full happy-path regression:
# issue -> exists -> get(active) -> revoke -> get(revoked)

NETWORK_DIR="${NETWORK_DIR:-/home/jatin/Justify/justify/fabric-samples/test-network}"
CC_NAME="${CC_NAME:-justifai_cert}"
CHANNEL="${CHANNEL:-mychannel}"
CERT_ID="${1:-cert-regression-$(date +%s)}"
CERT_HASH="${2:-hash-regression-001}"
IDENTITY_MSP_PATH="${IDENTITY_MSP_PATH:-$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/uniadmin2@org1.example.com/msp}"

export PATH="/home/jatin/Justify/justify/fabric-samples/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export FABRIC_CFG_PATH="/home/jatin/Justify/justify/fabric-samples/config"

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"
export CORE_PEER_MSPCONFIGPATH="$IDENTITY_MSP_PATH"

ORDERER_CA="$NETWORK_DIR/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"
PEER0_ORG1_CA="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"
PEER0_ORG2_CA="$NETWORK_DIR/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem"

echo "==> IssueCertificate for ${CERT_ID}"
peer chaincode invoke -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" \
  -C "$CHANNEL" -n "$CC_NAME" \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
  --waitForEvent \
  -c "{\"Args\":[\"IssueCertificate\",\"${CERT_ID}\",\"${CERT_HASH}\"]}"

echo "==> CertificateExists after issue"
peer chaincode query -C "$CHANNEL" -n "$CC_NAME" \
  -c "{\"Args\":[\"CertificateExists\",\"${CERT_ID}\"]}"

echo
echo "==> GetCertificate after issue (expect status active)"
peer chaincode query -C "$CHANNEL" -n "$CC_NAME" \
  -c "{\"Args\":[\"GetCertificate\",\"${CERT_ID}\"]}"

echo
echo "==> RevokeCertificate for ${CERT_ID}"
peer chaincode invoke -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" \
  -C "$CHANNEL" -n "$CC_NAME" \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
  --waitForEvent \
  -c "{\"Args\":[\"RevokeCertificate\",\"${CERT_ID}\"]}"

echo "==> GetCertificate after revoke (expect status revoked)"
peer chaincode query -C "$CHANNEL" -n "$CC_NAME" \
  -c "{\"Args\":[\"GetCertificate\",\"${CERT_ID}\"]}"

echo
echo "RBAC regression happy-path complete."
