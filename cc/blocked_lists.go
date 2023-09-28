package cc

import (
	"fmt"

	pb "github.com/atomyze-foundation/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

// ListType is a type of list
type ListType string

const (
	// BlackList is a list of blacklisted addresses
	BlackList ListType = "black"
	// GrayList is a list of graylisted addresses
	GrayList ListType = "gray"
)

func (lt ListType) String() string {
	return string(lt)
}

// AddToList sets address to 'gray list' or 'black list'
// arg[0] - address
// arg[1] - "gray" of "black"
func (c *ACL) AddToList(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const requiredArgsCount = 2
	if argsNum != requiredArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, attribute ('gray' or 'black')", argsNum))
	}

	if err := c.checkCert(stub); err != nil {
		return shim.Error(fmt.Sprintf("unauthorized: %s", err.Error()))
	}

	if len(args[0]) == 0 {
		return shim.Error(ErrEmptyAddress)
	}

	if args[1] != GrayList.String() && args[1] != BlackList.String() {
		return shim.Error("%s is not valid list type, accepted 'black' or 'gray' only")
	}

	addrArg := args[0]
	color := ListType(args[1])

	if err := changeListStatus(stub, addrArg, color, true); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// DelFromList removes address from gray list or black list
// arg[0] - address
// arg[1] - "gray" of "black"
func (c *ACL) DelFromList(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const requiredArgsCount = 2
	if argsNum != requiredArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, "+
			"attribute ('gray' or 'black')", argsNum))
	}

	if err := c.checkCert(stub); err != nil {
		return shim.Error(fmt.Sprintf("unauthorized: %s", err.Error()))
	}

	if len(args[0]) == 0 {
		return shim.Error(ErrEmptyAddress)
	}

	if args[1] != GrayList.String() && args[1] != BlackList.String() {
		return shim.Error("marker not specified (black or white list)")
	}

	addrArg := args[0]
	color := ListType(args[1])

	if err := changeListStatus(stub, addrArg, color, false); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func changeListStatus(stub shim.ChaincodeStubInterface, addr string, color ListType, status bool) error {
	cKey, err := stub.CreateCompositeKey(accInfoPrefix, []string{addr})
	if err != nil {
		return err
	}
	info, err := getAccountInfo(stub, addr)
	if err != nil {
		return err
	}

	switch color {
	case GrayList:
		info.GrayListed = status
	case BlackList:
		info.BlackListed = status
	}

	infoMarshaled, err := proto.Marshal(info)
	if err != nil {
		return err
	}

	return stub.PutState(cKey, infoMarshaled)
}

// checkGrayList get address from ledger and check it is in gray list
func checkGrayList(stub shim.ChaincodeStubInterface, addrEncoded string) error {
	accInfoKey, err := stub.CreateCompositeKey(accInfoPrefix, []string{addrEncoded})
	if err != nil {
		return err
	}

	accInfo, err := stub.GetState(accInfoKey)
	if err != nil {
		return err
	}

	var info pb.AccountInfo
	if err = proto.Unmarshal(accInfo, &info); err != nil {
		return err
	}

	if info.GrayListed {
		return fmt.Errorf("address %s is graylisted", addrEncoded)
	}
	return nil
}
