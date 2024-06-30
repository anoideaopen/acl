package cc

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

type GetAccountsInfoRequest struct {
	Items []GetAccountsInfoItem
}

type GetAccountsInfoItem struct {
	Method string
	Args   []string
}

type GetAccountsInfoResponse struct {
	Responses []peer.Response
}

func (c *ACL) GetAccountsInfo(stub shim.ChaincodeStubInterface, _ []string) peer.Response {
	args := stub.GetArgs()
	if len(args) == 1 {
		return shim.Error(fmt.Sprintf("incorrect number of arguments. expecting more 1 but found %d", len(args)))
	}

	getAccountsInfoRequest := &GetAccountsInfoRequest{}
	err := json.Unmarshal(args[1], getAccountsInfoRequest)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed unmarshal GetAccountsInfoRequest: %s", err))
	}

	responses := make([]peer.Response, 0)
	for _, item := range getAccountsInfoRequest.Items {
		var response peer.Response
		switch item.Method {
		case "getAccountInfo":
			for _, address := range item.Args {
				response = c.GetAccountInfo(stub, []string{address})
				responses = append(responses, response)
			}
		case "checkAddress":
			for _, addressBase58Check := range item.Args {
				response = c.CheckAddress(stub, []string{addressBase58Check})
				responses = append(responses, response)
			}
		case "checkKeys":
			for _, publicKey := range item.Args {
				response = c.CheckKeys(stub, []string{publicKey})
				responses = append(responses, response)
			}
		default:
			responses = append(responses, shim.Error(fmt.Sprintf("failed get accountInfo: unknown method %s", item.Method)))
		}
	}

	bytes, err := json.Marshal(GetAccountsInfoResponse{Responses: responses})
	if err != nil {
		return shim.Error(fmt.Sprintf("failed to marshal GetAccountsInfoResponse: %s", err))
	}
	return shim.Success(bytes)
}
