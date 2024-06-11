package cc

import (
	"errors"
	"fmt"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"google.golang.org/protobuf/encoding/protojson"
)

// matrix keys
const (
	operationKey = "acl_access_matrix_operation"
	addressKey   = "acl_access_matrix_address"
)

// AddRights adds rights to the access matrix
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) AddRights(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen,gocognit,gocyclo
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
	operationCompositeKey, err := stub.CreateCompositeKey(operationKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(operationCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, addresses); err != nil {
			if err = proto.Unmarshal(rawAddresses, addresses); err != nil {
				return shim.Error(err.Error())
			}
		}
	}

	addressFound := false
	for _, existedAddr := range addresses.GetAddresses() {
		if existedAddr.AddrString() == address.AddrString() {
			addressFound = true
			break
		}
	}

	if !addressFound {
		addresses.Addresses = append(addresses.Addresses, address)
		rawAddresses, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
		err = stub.PutState(operationCompositeKey, rawAddresses)
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
		if err = protojson.Unmarshal(rawAccountRights, accountRights); err != nil {
			if err = proto.Unmarshal(rawAccountRights, accountRights); err != nil {
				return shim.Error(err.Error())
			}
		}
	}

	rightFound := false
	for _, rightExists := range accountRights.GetRights() {
		if rightExists.GetChannelName() == channelName &&
			rightExists.GetChaincodeName() == chaincodeName &&
			rightExists.GetRoleName() == roleName &&
			rightExists.GetOperationName() == operationName &&
			rightExists.GetAddress().AddrString() == address.AddrString() {
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
		rawAccountRights, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(accountRights)
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
	operationCompositeKey, err := stub.CreateCompositeKey(operationKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(operationCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, addresses); err != nil {
			if err = proto.Unmarshal(rawAddresses, addresses); err != nil {
				return shim.Error(err.Error())
			}
		}
	}

	for i, existedAddr := range addresses.GetAddresses() {
		if existedAddr.AddrString() == address.AddrString() {
			addresses.Addresses = append(addresses.Addresses[:i], addresses.GetAddresses()[i+1:]...)
			rawAddresses, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(addresses)
			if err != nil {
				return shim.Error(err.Error())
			}
			err = stub.PutState(operationCompositeKey, rawAddresses)
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
		if err = protojson.Unmarshal(rawAccountRights, accountRights); err != nil {
			if err = proto.Unmarshal(rawAccountRights, accountRights); err != nil {
				return shim.Error(err.Error())
			}
		}
	}

	for i, rightExists := range accountRights.GetRights() {
		if rightExists.GetChannelName() == channelName && rightExists.GetChaincodeName() == chaincodeName &&
			rightExists.GetRoleName() == roleName && rightExists.GetOperationName() == operationName &&
			rightExists.GetAddress().String() == address.String() {
			accountRights.Rights = append(accountRights.Rights[:i], accountRights.GetRights()[i+1:]...)
			rawAccountRights, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(accountRights)
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
func (c *ACL) GetAccountOperationRight(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	result, err := c.getAccountOperationRight(stub, args)
	if err != nil {
		return shim.Error(err.Error())
	}

	rawResult, err := proto.Marshal(result)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(rawResult)
}

// GetAccountOperationRightJson checks address have rights for the operation
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) GetAccountOperationRightJSON(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	result, err := c.getAccountOperationRight(stub, args)
	if err != nil {
		return shim.Error(err.Error())
	}

	rawResult, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(result)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(rawResult)
}

func (c *ACL) getAccountOperationRight(stub shim.ChaincodeStubInterface, args []string) (*pb.HaveRight, error) { //nolint:funlen
	argsNum := len(args)
	const requiredArgsCount = 5
	if argsNum != requiredArgsCount {
		return nil, fmt.Errorf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, role name, operation name and user address")
	}

	canCall, err := c.isCalledFromChaincodeOrAdmin(stub)
	if err != nil {
		return nil, fmt.Errorf(errs.ErrCallAthFailed, err.Error())
	}
	if !canCall {
		return nil, errors.New(errs.ErrCalledNotCCOrAdmin)
	}

	channelName := args[0]
	chaincodeName := args[1]
	roleName := args[2]
	operationName := args[3]
	addressEncoded := args[4]

	if len(channelName) == 0 {
		return nil, errors.New(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return nil, errors.New(errs.ErrEmptyChaincodeName)
	}

	if len(roleName) == 0 {
		return nil, errors.New(errs.ErrEmptyRoleName)
	}

	if len(addressEncoded) == 0 {
		return nil, errors.New(errs.ErrEmptyAddress)
	}

	address, err := c.retrieveAndVerifySignedAddress(stub, addressEncoded)
	if err != nil {
		return nil, err
	}

	operationCompositeKey, err := stub.CreateCompositeKey(operationKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return nil, err
	}

	rawAddresses, err := stub.GetState(operationCompositeKey)
	if err != nil {
		return nil, err
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, addresses); err != nil {
			if err = proto.Unmarshal(rawAddresses, addresses); err != nil {
				return nil, err
			}
		}
	}

	result := &pb.HaveRight{HaveRight: false}

	for _, existedAddr := range addresses.GetAddresses() {
		if existedAddr.AddrString() == address.AddrString() {
			result.HaveRight = true
			break
		}
	}

	return result, nil
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
	accountRights := &pb.AccountRights{
		Address: address,
		Rights:  []*pb.Right{},
	}
	if err = protojson.Unmarshal(rawAccountRights, accountRights); err != nil {
		if err = proto.Unmarshal(rawAccountRights, accountRights); err != nil {
			return shim.Error(err.Error())
		}
	}
	rawAccountRights, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(accountRights)
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

	operationCompositeKey, err := stub.CreateCompositeKey(operationKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(operationCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, addresses); err != nil {
			if err = proto.Unmarshal(rawAddresses, addresses); err != nil {
				return shim.Error(err.Error())
			}
		}
	}

	rights := make([]*pb.Right, 0, len(addresses.GetAddresses()))
	for _, existedAddr := range addresses.GetAddresses() {
		rights = append(rights, &pb.Right{
			ChannelName:   channelName,
			ChaincodeName: chaincodeName,
			RoleName:      roleName,
			OperationName: operationName,
			Address:       existedAddr,
			HaveRight:     &pb.HaveRight{HaveRight: true},
		})
	}

	rawRights, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(&pb.OperationRights{OperationName: operationName, Rights: rights})
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(rawRights)
}

// isCalledFromChaincodeOrAdmin checks that function called from another chaincode or by acl admin
func (c *ACL) isCalledFromChaincodeOrAdmin(stub shim.ChaincodeStubInterface) (bool, error) {
	ccIsSet, err := calledFromChaincode(stub, c.config.GetCcName())
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
