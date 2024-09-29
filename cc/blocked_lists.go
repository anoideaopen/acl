package cc

import (
	"errors"
	"fmt"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

type ListType string

const (
	BlackList ListType = "black"
	GrayList  ListType = "gray"
)

func (lt ListType) String() string {
	return string(lt)
}

// AddToList sets address to 'gray list' or 'black list'
// arg[0] - address
// arg[1] - "gray" of "black"
func (c *ACL) AddToList(stub shim.ChaincodeStubInterface, args []string) error {
	const requiredArgsCount = 2

	argsNum := len(args)
	if argsNum != requiredArgsCount {
		return fmt.Errorf("incorrect number of arguments: %d, but this method expects: address, attribute ('gray' or 'black')", argsNum)
	}

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	if len(args[0]) == 0 {
		return errors.New(errs.ErrEmptyAddress)
	}

	if args[1] != GrayList.String() && args[1] != BlackList.String() {
		return fmt.Errorf("%s is not valid list type, accepted 'black' or 'gray' only", args[1])
	}

	addrArg := args[0]
	color := ListType(args[1])

	if err := updateListStatus(stub, addrArg, color, true); err != nil {
		return fmt.Errorf("failed to update list status: %w", err)
	}

	return nil
}

// DelFromList removes address from gray list or black list
// arg[0] - address
// arg[1] - "gray" of "black"
func (c *ACL) DelFromList(stub shim.ChaincodeStubInterface, args []string) error {
	const requiredArgsCount = 2

	argsNum := len(args)
	if argsNum != requiredArgsCount {
		return fmt.Errorf("incorrect number of arguments: %d, but this method expects: address, "+
			"attribute ('gray' or 'black')", argsNum)
	}

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	if len(args[0]) == 0 {
		return errors.New(errs.ErrEmptyAddress)
	}

	if args[1] != GrayList.String() && args[1] != BlackList.String() {
		return fmt.Errorf("%s is not valid list type, accepted 'black' only", args[0])
	}

	addrArg := args[0]
	color := ListType(args[1])

	if err := updateListStatus(stub, addrArg, color, false); err != nil {
		return fmt.Errorf("failed to update list status: %w", err)
	}

	return nil
}

// changeListStatus updates the grayList or blacklist status of an address in the account information.
func updateListStatus(
	stub shim.ChaincodeStubInterface,
	base58Address string,
	listType ListType,
	newStatus bool,
) error {
	accountInfoCompositeKey, err := compositekey.AccountInfo(stub, base58Address)
	if err != nil {
		return err
	}
	accountInfo, err := getAccountInfo(stub, base58Address)
	if err != nil {
		return err
	}

	switch listType {
	case GrayList:
		accountInfo.GrayListed = newStatus
	case BlackList:
		accountInfo.BlackListed = newStatus
	}

	marshaledAccountInfo, err := proto.Marshal(accountInfo)
	if err != nil {
		return err
	}

	return stub.PutState(accountInfoCompositeKey, marshaledAccountInfo)
}

// verifyAddressNotGrayListed checks if the given base58-encoded address is not on the gray list.
func verifyAddressNotGrayListed(stub shim.ChaincodeStubInterface, base58EncodedAddress string) error {
	accountInfoCompositeKey, err := compositekey.AccountInfo(stub, base58EncodedAddress)
	if err != nil {
		return err
	}

	accountInfoBytes, err := stub.GetState(accountInfoCompositeKey)
	if err != nil {
		return err
	}

	var accountInfo pb.AccountInfo
	if err = proto.Unmarshal(accountInfoBytes, &accountInfo); err != nil {
		return err
	}

	if accountInfo.GetGrayListed() {
		return fmt.Errorf("address %s is graylisted", base58EncodedAddress)
	}
	return nil
}
