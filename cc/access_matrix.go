package cc

import (
	"fmt"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

// matrix keys
const (
	operKey    = "acl_access_matrix_operation"
	addressKey = "acl_access_matrix_address"
)

// AddRights adds rights to the access matrix
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) AddRights(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen,gocognit
	argsNum := len(args)
	const requiredArgsCount = 5
	if argsNum != requiredArgsCount {
		errMsg := fmt.Sprintf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, role name, operation name and user address")
		return shim.Error(errMsg)
	}

	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorized+": %s", err.Error()))
	}

	channelName := args[0]
	chaincodeName := args[1]
	roleName := args[2]
	operationName := args[3]
	addressEncoded := args[4]

	if len(channelName) == 0 {
		return shim.Error(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return shim.Error(errs.ErrEmptyChaincodeName)
	}

	if len(roleName) == 0 {
		return shim.Error(errs.ErrEmptyRoleName)
	}

	if len(addressEncoded) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}

	address, err := c.retrieveAndVerifySignedAddress(stub, addressEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}

	// adding operation right
	operCompositeKey, err := stub.CreateCompositeKey(operKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(operCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = proto.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	addressFound := false
	for _, existedAddr := range addresses.Addresses {
		if existedAddr.AddrString() == address.AddrString() {
			addressFound = true
			break
		}
	}

	if !addressFound {
		addresses.Addresses = append(addresses.Addresses, address)
		rawAddresses, err = proto.Marshal(addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
		err = stub.PutState(operCompositeKey, rawAddresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	// adding account right
	accountCompositeKey, err := stub.CreateCompositeKey(addressKey, []string{address.AddrString()})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAccountRights, err := stub.GetState(accountCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}

	accountRights := &pb.AccountRights{
		Address: address,
		Rights:  []*pb.Right{},
	}
	if len(rawAccountRights) != 0 {
		err = proto.Unmarshal(rawAccountRights, accountRights)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	rightFound := false
	for _, rightExists := range accountRights.Rights {
		if rightExists.ChannelName == channelName &&
			rightExists.ChaincodeName == chaincodeName &&
			rightExists.RoleName == roleName &&
			rightExists.OperationName == operationName &&
			rightExists.Address.AddrString() == address.AddrString() {
			rightFound = true
			break
		}
	}

	if !rightFound {
		accountRights.Rights = append(accountRights.Rights, &pb.Right{
			ChannelName:   channelName,
			ChaincodeName: chaincodeName,
			RoleName:      roleName,
			OperationName: operationName,
			Address:       address,
			HaveRight:     &pb.HaveRight{HaveRight: true},
		})
		rawAccountRights, err = proto.Marshal(accountRights)
		if err != nil {
			return shim.Error(err.Error())
		}
		err = stub.PutState(accountCompositeKey, rawAccountRights)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	return shim.Success(nil)
}

// RemoveRights removes rights from the access matrix
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) RemoveRights(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen,gocognit
	argsNum := len(args)
	const requiredArgsCount = 5
	if argsNum != requiredArgsCount {
		errMsg := fmt.Sprintf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, role name, operation name and user address")
		return shim.Error(errMsg)
	}

	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorized+": %s", err.Error()))
	}

	channelName := args[0]
	chaincodeName := args[1]
	roleName := args[2]
	operationName := args[3]
	addressEncoded := args[4]

	address, err := c.retrieveAndVerifySignedAddress(stub, addressEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}

	// removing operation right
	operCompositeKey, err := stub.CreateCompositeKey(operKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(operCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = proto.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	for i, existedAddr := range addresses.Addresses {
		if existedAddr.AddrString() == address.AddrString() {
			addresses.Addresses = append(addresses.Addresses[:i], addresses.Addresses[i+1:]...)
			rawAddresses, err = proto.Marshal(addresses)
			if err != nil {
				return shim.Error(err.Error())
			}
			err = stub.PutState(operCompositeKey, rawAddresses)
			if err != nil {
				return shim.Error(err.Error())
			}
			break
		}
	}

	// removing account right
	accountCompositeKey, err := stub.CreateCompositeKey(addressKey, []string{address.AddrString()})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAccountRights, err := stub.GetState(accountCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}

	accountRights := &pb.AccountRights{
		Address: address,
		Rights:  []*pb.Right{},
	}
	if len(rawAccountRights) != 0 {
		err = proto.Unmarshal(rawAccountRights, accountRights)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	for i, rightExists := range accountRights.Rights {
		if rightExists.ChannelName == channelName && rightExists.ChaincodeName == chaincodeName &&
			rightExists.RoleName == roleName && rightExists.OperationName == operationName &&
			rightExists.Address.String() == address.String() {
			accountRights.Rights = append(accountRights.Rights[:i], accountRights.Rights[i+1:]...)
			rawAccountRights, err = proto.Marshal(accountRights)
			if err != nil {
				return shim.Error(err.Error())
			}
			err = stub.PutState(accountCompositeKey, rawAccountRights)
			if err != nil {
				return shim.Error(err.Error())
			}
			break
		}
	}

	return shim.Success(nil)
}

// GetAccountOperationRight checks address have rights for the operation
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) GetAccountOperationRight(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen
	argsNum := len(args)
	const requiredArgsCount = 5
	if argsNum != requiredArgsCount {
		errMsg := fmt.Sprintf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, role name, operation name and user address")
		return shim.Error(errMsg)
	}

	canCall, err := c.isCalledFromChaincodeOrAdmin(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrCallAthFailed, err.Error()))
	}
	if !canCall {
		return shim.Error(errs.ErrCalledNotCCOrAdmin)
	}

	channelName := args[0]
	chaincodeName := args[1]
	roleName := args[2]
	operationName := args[3]
	addressEncoded := args[4]

	if len(channelName) == 0 {
		return shim.Error(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return shim.Error(errs.ErrEmptyChaincodeName)
	}

	if len(roleName) == 0 {
		return shim.Error(errs.ErrEmptyRoleName)
	}

	if len(addressEncoded) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}

	address, err := c.retrieveAndVerifySignedAddress(stub, addressEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}

	operCompositeKey, err := stub.CreateCompositeKey(operKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(operCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = proto.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	result := &pb.HaveRight{HaveRight: false}

	for _, existedAddr := range addresses.Addresses {
		if existedAddr.AddrString() == address.AddrString() {
			result.HaveRight = true
			break
		}
	}

	rawResult, err := proto.Marshal(result)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(rawResult)
}

// GetAccountAllRights returns all operations specified account have right to execute
// args[0] -> addressEncoded
func (c *ACL) GetAccountAllRights(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const argsCount = 1
	if argsNum != argsCount {
		errMsg := fmt.Sprintf(errs.ErrArgumentsCount, argsNum, "user address")
		return shim.Error(errMsg)
	}

	canCall, err := c.isCalledFromChaincodeOrAdmin(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrCallAthFailed, err.Error()))
	}
	if !canCall {
		return shim.Error(errs.ErrCalledNotCCOrAdmin)
	}

	addressEncoded := args[0]
	if len(addressEncoded) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}

	address, err := c.retrieveAndVerifySignedAddress(stub, addressEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}

	key, err := stub.CreateCompositeKey(addressKey, []string{address.AddrString()})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAccountRights, err := stub.GetState(key)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(rawAccountRights)
}

// GetOperationAllRights returns all accounts having right to execute specified operation
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
func (c *ACL) GetOperationAllRights(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const requiredArgsCount = 4
	if argsNum != requiredArgsCount {
		errMsg := fmt.Sprintf(errs.ErrArgumentsCount, argsNum, "channel name, chaincode name, role name and operation name")
		return shim.Error(errMsg)
	}

	canCall, err := c.isCalledFromChaincodeOrAdmin(stub)
	if err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrCallAthFailed, err.Error()))
	}
	if !canCall {
		return shim.Error(errs.ErrCalledNotCCOrAdmin)
	}

	channelName := args[0]
	chaincodeName := args[1]
	roleName := args[2]
	operationName := args[3]

	if len(channelName) == 0 {
		return shim.Error(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return shim.Error(errs.ErrEmptyChaincodeName)
	}

	if len(roleName) == 0 {
		return shim.Error(errs.ErrEmptyRoleName)
	}

	operCompositeKey, err := stub.CreateCompositeKey(operKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(operCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = proto.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	rights := make([]*pb.Right, 0, len(addresses.Addresses))
	for _, existedAddr := range addresses.Addresses {
		rights = append(rights, &pb.Right{
			ChannelName:   channelName,
			ChaincodeName: chaincodeName,
			RoleName:      roleName,
			OperationName: operationName,
			Address:       existedAddr,
			HaveRight:     &pb.HaveRight{HaveRight: true},
		})
	}

	rawRights, err := proto.Marshal(&pb.OperationRights{OperationName: operationName, Rights: rights})
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(rawRights)
}

// isCalledFromChaincodeOrAdmin checks that function called from another chaincode or by acl admin
func (c *ACL) isCalledFromChaincodeOrAdmin(stub shim.ChaincodeStubInterface) (bool, error) {
	ccIsSet, err := calledFromChaincode(stub, c.config.CCName)
	if err != nil {
		return false, err
	}
	// called from chaincode check
	if ccIsSet {
		return true, nil
	}

	// called by admin check
	if err = c.verifyAccess(stub); err != nil {
		if err.Error() == errs.ErrCallerNotAdmin {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// calledFromChaincode get chaincode name from proposal; if errors occurs return false, error
func calledFromChaincode(stub shim.ChaincodeStubInterface, ccNameEtl string) (bool, error) {
	ccName, err := helpers.ParseCCName(stub)
	if err != nil {
		return false, err
	}

	if ccName != ccNameEtl {
		return true, nil
	}

	return false, nil
}
