package cc

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

var getAccountInfoMethodHandlersMap map[string]func(shim.ChaincodeStubInterface, []string) peer.Response

func (c *ACL) getAccountInfoHandlers() map[string]func(shim.ChaincodeStubInterface, []string) peer.Response {
	if getAccountInfoMethodHandlersMap != nil {
		return getAccountInfoMethodHandlersMap
	}
	getAccountInfoMethodHandlersMap = map[string]func(shim.ChaincodeStubInterface, []string) peer.Response{
		"getAccountInfo": c.GetAccountInfo,
		"checkAddress":   c.CheckAddress,
		"checkKeys":      c.CheckKeys,
	}
	return getAccountInfoMethodHandlersMap
}

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

	method := args[0]
	methodArgs := args[1:]
	handler, ok := c.getAccountInfoHandlers()[method]
	if !ok {
		return shim.Error(fmt.Sprintf("failed get accounts info: unknown method '%s'", method))
	}
	return handler(stub, methodArgs)
}
