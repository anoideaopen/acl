package cc

import (
	"encoding/json"
	"fmt"

	"github.com/anoideaopen/acl/cc/querystub"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

func (c *ACL) GetAccountsInfo(stub shim.ChaincodeStubInterface, _ []string) peer.Response {
	responses := make([]peer.Response, 0)
	for _, bytes := range stub.GetArgs()[1:] {
		response := c.handleGetAccountsInfoItem(stub, bytes)
		responses = append(responses, response)
	}

	bytes, err := json.Marshal(responses)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed get accounts info: marshal GetAccountsInfoResponse: %s", err))
	}
	return shim.Success(bytes)
}

func (c *ACL) handleGetAccountsInfoItem(stub shim.ChaincodeStubInterface, b []byte) peer.Response {
	var args []string
	err := json.Unmarshal(b, &args)
	if err != nil {
		return shim.Error(fmt.Sprintf("unmarshal args failed '%s': %s", string(b), err))
	}

	if len(args) < 2 {
		return shim.Error(fmt.Sprintf("not enough arguments '%s'", string(b)))
	}

	fn := args[0]
	methodArgs := args[1:]
	ccInvoke, ok := c.methods[fn]
	if !ok {
		return shim.Error(fmt.Sprintf("failed get accounts info: unknown method '%s' in tx %s", fn, stub.GetTxID()))
	}

	stub = querystub.NewQueryStub(stub, args...)

	return ccInvoke(stub, methodArgs)
}
