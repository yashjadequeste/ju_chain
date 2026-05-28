package main

import (
	"log"

	"justifai_chaincode/chaincode"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	contract := new(chaincode.CertificateContract)

	cc, err := contractapi.NewChaincode(contract)
	if err != nil {
		log.Panicf("error creating certificate chaincode: %v", err)
	}

	if err := cc.Start(); err != nil {
		log.Panicf("error starting certificate chaincode: %v", err)
	}
}
