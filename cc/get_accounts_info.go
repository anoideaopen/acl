package cc

import (
	"encoding/json"
	"fmt"

	"github.com/anoideaopen/acl/cc/querystub"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

func (c *ACL) GetAccountsInfo(stub shim.ChaincodeStubInterface, _ []string) ([]byte, error) {
	responses := make([]peer.Response, 0)
	for _, bytes := range stub.GetArgs()[1:] {
		payload, err := c.handleGetAccountsInfoItem(stub, bytes)
		if err != nil {
			responses = append(responses, shim.Error(err.Error()))
		} else {
			responses = append(responses, shim.Success(payload))
		}
	}

	bytes, err := json.Marshal(responses)
	if err != nil {
		return nil, fmt.Errorf("failed get accounts info: marshal GetAccountsInfoResponse: %w", err)
	}

	return bytes, nil
}

func (c *ACL) handleGetAccountsInfoItem(stub shim.ChaincodeStubInterface, b []byte) ([]byte, error) {
	var args []string

	if err := json.Unmarshal(b, &args); err != nil {
		return nil, fmt.Errorf("failed unmarshalling arguments: %w", err)
	}

	if len(args) < 2 {
		return nil, fmt.Errorf("not enough arguments '%s'", string(b))
	}

	var (
		fn         = args[0]
		methodArgs = args[1:]
	)

	ccInvoke, ok := c.methods[fn]
	if !ok {
		return nil, fmt.Errorf("failed get accounts info: unknown method '%s' in tx %s", fn, stub.GetTxID())
	}

	stub = querystub.NewQueryStub(stub, args...)

	return ccInvoke(stub, methodArgs)
}
