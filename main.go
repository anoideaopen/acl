package main

import (
	"log"

	acl "github.com/anoideaopen/acl/cc"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

func main() {
	if err := shim.Start(acl.New()); err != nil {
		log.Fatal(err)
	}
}
