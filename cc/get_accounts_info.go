package cc

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

func (c *ACL) GetAccountsInfo(stub shim.ChaincodeStubInterface, _ []string) peer.Response {
	responses := make([]peer.Response, 0)
	for _, b := range stub.GetArgs()[1:] {
		var args []string
		err := json.Unmarshal(b, &args)
		if err != nil {
			return shim.Error(fmt.Sprintf("unmarshal args failed '%s': %s", string(b), err))
		}

		if len(args) < 2 {
			return shim.Error(fmt.Sprintf("not enough arguments '%s'", string(b)))
		}

		var response peer.Response
		switch args[0] {
		case "getAccountInfo":
			for _, address := range args[1:] {
				response = c.GetAccountInfo(stub, []string{address})
				responses = append(responses, response)
			}
		case "checkAddress":
			for _, addressBase58Check := range args[1:] {
				response = c.CheckAddress(stub, []string{addressBase58Check})
				responses = append(responses, response)
			}
		case "checkKeys":
			for _, publicKey := range args[1:] {
				response = c.CheckKeys(stub, []string{publicKey})
				responses = append(responses, response)
			}
		default:
			responses = append(responses, shim.Error(fmt.Sprintf("failed get accounts info: unknown method '%s'", args[0])))
		}
	}

	bytes, err := json.Marshal(responses)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed get accounts info: marshal GetAccountsInfoResponse: %s", err))
	}
	return shim.Success(bytes)
}
