package cc

import (
	"errors"
	"fmt"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"google.golang.org/protobuf/encoding/protojson"
)

// matrix keys
const (
	operationKey       = "acl_access_matrix_operation"
	addressKey         = "acl_access_matrix_address"
	holderAddressesKey = "acl_access_matrix_principal_addresses"
)

// AddRights adds rights to the access matrix
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) AddRights(stub shim.ChaincodeStubInterface, args []string) error { //nolint:funlen,gocognit,gocyclo
	const requiredArgsCount = 5

	argsNum := len(args)
	if argsNum != requiredArgsCount {
		return fmt.Errorf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, role name, operation name and user address")
	}

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	var (
		channelName    = args[0]
		chaincodeName  = args[1]
		roleName       = args[2]
		operationName  = args[3]
		addressEncoded = args[4]
	)
	if len(channelName) == 0 {
		return errors.New(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return errors.New(errs.ErrEmptyChaincodeName)
	}

	if len(roleName) == 0 {
		return errors.New(errs.ErrEmptyRoleName)
	}

	if len(addressEncoded) == 0 {
		return errors.New(errs.ErrEmptyAddress)
	}

	address, err := c.retrieveAndVerifySignedAddress(stub, addressEncoded)
	if err != nil {
		return fmt.Errorf("failed retrieving signed address: %w", err)
	}

	// adding operation right
	operationCompositeKey, err := stub.CreateCompositeKey(operationKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return fmt.Errorf("failed creating composite key: %w", err)
	}

	rawAddresses, err := stub.GetState(operationCompositeKey)
	if err != nil {
		return fmt.Errorf("failed reading address from state: %w", err)
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, addresses); err != nil {
			if err = proto.Unmarshal(rawAddresses, addresses); err != nil {
				return fmt.Errorf("failed unmarshalling address: %w", err)
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
			return fmt.Errorf("failed marshalling addresses: %w", err)
		}
		err = stub.PutState(operationCompositeKey, rawAddresses)
		if err != nil {
			return fmt.Errorf("failed putting address to state: %w", err)
		}
	}

	// adding account right
	accountCompositeKey, err := stub.CreateCompositeKey(addressKey, []string{address.AddrString()})
	if err != nil {
		return fmt.Errorf("failed creating composite key: %w", err)
	}

	rawAccountRights, err := stub.GetState(accountCompositeKey)
	if err != nil {
		return fmt.Errorf("failed reading account rights: %w", err)
	}

	accountRights := &pb.AccountRights{
		Address: address,
		Rights:  []*pb.Right{},
	}
	if len(rawAccountRights) != 0 {
		if err = protojson.Unmarshal(rawAccountRights, accountRights); err != nil {
			if err = proto.Unmarshal(rawAccountRights, accountRights); err != nil {
				return fmt.Errorf("failed unmarshalling account rights: %w", err)
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
			return fmt.Errorf("failed marshalling account rights: %w", err)
		}
		err = stub.PutState(accountCompositeKey, rawAccountRights)
		if err != nil {
			return fmt.Errorf("failed putting account rights to state: %w", err)
		}
	}

	return nil
}

// RemoveRights removes rights from the access matrix
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) RemoveRights(stub shim.ChaincodeStubInterface, args []string) error { //nolint:funlen,gocognit
	const requiredArgsCount = 5

	argsNum := len(args)
	if argsNum != requiredArgsCount {
		return fmt.Errorf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, role name, operation name and user address")
	}

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	channelName := args[0]
	chaincodeName := args[1]
	roleName := args[2]
	operationName := args[3]
	addressEncoded := args[4]

	address, err := c.retrieveAndVerifySignedAddress(stub, addressEncoded)
	if err != nil {
		return fmt.Errorf("failed retrieving signed address: %w", err)
	}

	// removing operation right
	operationCompositeKey, err := stub.CreateCompositeKey(operationKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return fmt.Errorf("failed creating composite key: %w", err)
	}

	rawAddresses, err := stub.GetState(operationCompositeKey)
	if err != nil {
		return fmt.Errorf("failed reading address from state: %w", err)
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, addresses); err != nil {
			if err = proto.Unmarshal(rawAddresses, addresses); err != nil {
				return fmt.Errorf("failed unmarshalling address: %w", err)
			}
		}
	}

	for i, existedAddr := range addresses.GetAddresses() {
		if existedAddr.AddrString() == address.AddrString() {
			addresses.Addresses = append(addresses.Addresses[:i], addresses.GetAddresses()[i+1:]...)
			rawAddresses, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(addresses)
			if err != nil {
				return fmt.Errorf("failed marshalling addresses: %w", err)
			}
			err = stub.PutState(operationCompositeKey, rawAddresses)
			if err != nil {
				return fmt.Errorf("failed putting address to state: %w", err)
			}
			break
		}
	}

	// removing account right
	accountCompositeKey, err := stub.CreateCompositeKey(addressKey, []string{address.AddrString()})
	if err != nil {
		return fmt.Errorf("failed creating composite key: %w", err)
	}

	rawAccountRights, err := stub.GetState(accountCompositeKey)
	if err != nil {
		return fmt.Errorf("failed reading account rights: %w", err)
	}

	accountRights := &pb.AccountRights{
		Address: address,
		Rights:  []*pb.Right{},
	}
	if len(rawAccountRights) != 0 {
		if err = protojson.Unmarshal(rawAccountRights, accountRights); err != nil {
			if err = proto.Unmarshal(rawAccountRights, accountRights); err != nil {
				return fmt.Errorf("failed unmarshalling account rights: %w", err)
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
				return fmt.Errorf("failed marshalling account rights: %w", err)
			}
			err = stub.PutState(accountCompositeKey, rawAccountRights)
			if err != nil {
				return fmt.Errorf("failed putting account rights to state: %w", err)
			}
			break
		}
	}

	return nil
}

// GetAccountOperationRight checks address have rights for the operation
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) GetAccountOperationRight(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	result, err := c.getAccountOperationRight(stub, args)
	if err != nil {
		return nil, fmt.Errorf("failed getting operation right: %w", err)
	}

	rawResult, err := proto.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling operation right: %w", err)
	}

	return rawResult, nil
}

// GetAccountOperationRightJSON checks address have rights for the operation
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
// args[4] -> addressEncoded
func (c *ACL) GetAccountOperationRightJSON(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	result, err := c.getAccountOperationRight(stub, args)
	if err != nil {
		return nil, fmt.Errorf("failed getting operation right: %w", err)
	}

	rawResult, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling operation right: %w", err)
	}

	return rawResult, nil
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
func (c *ACL) GetAccountAllRights(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	const requiredArgsCount = 1

	argsNum := len(args)
	if argsNum != requiredArgsCount {
		return nil, fmt.Errorf(errs.ErrArgumentsCount, argsNum, "user address")
	}

	canCall, err := c.isCalledFromChaincodeOrAdmin(stub)
	if err != nil {
		return nil, fmt.Errorf(errs.ErrCallAthFailed, err.Error())
	}
	if !canCall {
		return nil, errors.New(errs.ErrCalledNotCCOrAdmin)
	}

	addressEncoded := args[0]
	if len(addressEncoded) == 0 {
		return nil, errors.New(errs.ErrEmptyAddress)
	}

	address, err := c.retrieveAndVerifySignedAddress(stub, addressEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving signed address: %w", err)
	}

	key, err := stub.CreateCompositeKey(addressKey, []string{address.AddrString()})
	if err != nil {
		return nil, fmt.Errorf("failed creating composite key: %w", err)
	}

	rawAccountRights, err := stub.GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed reading account rights: %w", err)
	}
	accountRights := &pb.AccountRights{
		Address: address,
		Rights:  []*pb.Right{},
	}
	if err = protojson.Unmarshal(rawAccountRights, accountRights); err != nil {
		if err = proto.Unmarshal(rawAccountRights, accountRights); err != nil {
			return nil, fmt.Errorf("failed unmarshalling account rights: %w", err)
		}
	}
	rawAccountRights, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(accountRights)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling account rights: %w", err)
	}

	return rawAccountRights, nil
}

// GetOperationAllRights returns all accounts having right to execute specified operation
// args[0] -> channelName
// args[1] -GetOperationAllRights> chaincodeName
// args[2] -> roleName
// args[3] -> operationName
func (c *ACL) GetOperationAllRights(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	const requiredArgsCount = 4

	argsNum := len(args)
	if argsNum != requiredArgsCount {
		return nil, fmt.Errorf(errs.ErrArgumentsCount, argsNum, "channel name, chaincode name, role name and operation name")
	}

	canCall, err := c.isCalledFromChaincodeOrAdmin(stub)
	if err != nil {
		return nil, fmt.Errorf(errs.ErrCallAthFailed, err.Error())
	}
	if !canCall {
		return nil, errors.New(errs.ErrCalledNotCCOrAdmin)
	}

	var (
		channelName   = args[0]
		chaincodeName = args[1]
		roleName      = args[2]
		operationName = args[3]
	)

	if len(channelName) == 0 {
		return nil, errors.New(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return nil, errors.New(errs.ErrEmptyChaincodeName)
	}

	if len(roleName) == 0 {
		return nil, errors.New(errs.ErrEmptyRoleName)
	}

	operationCompositeKey, err := stub.CreateCompositeKey(operationKey, []string{channelName, chaincodeName, roleName, operationName})
	if err != nil {
		return nil, fmt.Errorf("failed creating composite key: %w", err)
	}

	rawAddresses, err := stub.GetState(operationCompositeKey)
	if err != nil {
		return nil, fmt.Errorf("failed reading addresses from state: %w", err)
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, addresses); err != nil {
			if err = proto.Unmarshal(rawAddresses, addresses); err != nil {
				return nil, fmt.Errorf("failed unmarshalling addresses: %w", err)
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
		return nil, fmt.Errorf("failed marshalling operation rights: %w", err)
	}

	return rawRights, nil
}

// AddAddressForHolder adding principal address for holder
// args[0] -> channelName
// args[1] -> chaincodeName
// args[2] -> holderAddress
// args[3] -> principalAddress
func (c *ACL) AddAddressForHolder(stub shim.ChaincodeStubInterface, args []string) error {
	argsNum := len(args)
	const requiredArgsCount = 4
	if argsNum != requiredArgsCount {
		return fmt.Errorf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, holder address and principal address required")
	}

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorized+": %s", err.Error())
	}

	channelName := args[0]
	chaincodeName := args[1]
	holderAddressEncoded := args[2]
	principalAddressEncoded := args[3]

	if len(channelName) == 0 {
		return fmt.Errorf(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return fmt.Errorf(errs.ErrEmptyChaincodeName)
	}

	if len(holderAddressEncoded) == 0 {
		return fmt.Errorf(errs.ErrEmptyHolderAddress)
	}

	if len(principalAddressEncoded) == 0 {
		return fmt.Errorf(errs.ErrEmptyPrincipalAddress)
	}

	holderAddress, err := c.retrieveAndVerifySignedAddress(stub, holderAddressEncoded)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	principalAddress, err := c.retrieveAndVerifySignedAddress(stub, principalAddressEncoded)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	// adding address
	addressesCompositeKey, err := stub.CreateCompositeKey(holderAddressesKey, []string{channelName, chaincodeName, holderAddress.String()})
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	rawAddresses, err := stub.GetState(addressesCompositeKey)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	principalAddresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, principalAddresses); err != nil {
			return fmt.Errorf(err.Error())
		}
	}

	addressFound := false
	for _, existedAddr := range principalAddresses.GetAddresses() {
		if existedAddr.AddrString() == principalAddress.AddrString() {
			addressFound = true
			break
		}
	}

	if !addressFound {
		principalAddresses.Addresses = append(principalAddresses.Addresses, principalAddress)
		rawAddresses, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(principalAddresses)
		if err != nil {
			return fmt.Errorf(err.Error())
		}
		err = stub.PutState(addressesCompositeKey, rawAddresses)
		if err != nil {
			return fmt.Errorf(err.Error())
		}
	}

	return nil
}

// RemoveAddressFromHolder adding principal address for holder
// args[0] -> channelName
// args[1] -> chaincodeName
// args[2] -> holderAddress
// args[3] -> principalAddress
func (c *ACL) RemoveAddressFromHolder(stub shim.ChaincodeStubInterface, args []string) error {
	argsNum := len(args)
	const requiredArgsCount = 4
	if argsNum != requiredArgsCount {
		return fmt.Errorf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, holder address and principal address required")
	}

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorized+": %s", err.Error())
	}

	channelName := args[0]
	chaincodeName := args[1]
	holderAddressEncoded := args[2]
	principalAddressEncoded := args[3]

	if len(channelName) == 0 {
		return fmt.Errorf(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return fmt.Errorf(errs.ErrEmptyChaincodeName)
	}

	if len(holderAddressEncoded) == 0 {
		return fmt.Errorf(errs.ErrEmptyHolderAddress)
	}

	if len(principalAddressEncoded) == 0 {
		return fmt.Errorf(errs.ErrEmptyPrincipalAddress)
	}

	holderAddress, err := c.retrieveAndVerifySignedAddress(stub, holderAddressEncoded)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	principalAddress, err := c.retrieveAndVerifySignedAddress(stub, principalAddressEncoded)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	// removing address
	addressesCompositeKey, err := stub.CreateCompositeKey(holderAddressesKey, []string{channelName, chaincodeName, holderAddress.String()})
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	rawAddresses, err := stub.GetState(addressesCompositeKey)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	principalAddresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, principalAddresses); err != nil {
			return fmt.Errorf(err.Error())
		}
	}

	for i, existedAddr := range principalAddresses.GetAddresses() {
		if existedAddr.AddrString() == principalAddress.AddrString() {
			principalAddresses.Addresses = append(principalAddresses.Addresses[:i], principalAddresses.GetAddresses()[i+1:]...)
			rawAddresses, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(principalAddresses)
			if err != nil {
				return fmt.Errorf(err.Error())
			}
			err = stub.PutState(addressesCompositeKey, rawAddresses)
			if err != nil {
				return fmt.Errorf(err.Error())
			}
			break
		}
	}

	return nil
}

// GetAddressRightForHolder return if holder have right to access to principal address
// args[0] -> channelName
// args[1] -> chaincodeName
// args[2] -> holderAddress
// args[3] -> principalAddress
func (c *ACL) GetAddressRightForHolder(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	argsNum := len(args)
	const requiredArgsCount = 4
	if argsNum != requiredArgsCount {
		return nil, fmt.Errorf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name, holder address and principal address required")
	}

	// check if called from admin or chaincode
	canCall, err := c.isCalledFromChaincodeOrAdmin(stub)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf(errs.ErrCallAthFailed, err.Error()))
	}
	if !canCall {
		return nil, fmt.Errorf(errs.ErrCalledNotCCOrAdmin)
	}

	channelName := args[0]
	chaincodeName := args[1]
	holderAddressEncoded := args[2]
	principalAddressEncoded := args[3]

	if len(channelName) == 0 {
		return nil, fmt.Errorf(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return nil, fmt.Errorf(errs.ErrEmptyChaincodeName)
	}

	if len(holderAddressEncoded) == 0 {
		return nil, fmt.Errorf(errs.ErrEmptyHolderAddress)
	}

	if len(principalAddressEncoded) == 0 {
		return nil, fmt.Errorf(errs.ErrEmptyPrincipalAddress)
	}

	holderAddress, err := c.retrieveAndVerifySignedAddress(stub, holderAddressEncoded)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	principalAddress, err := c.retrieveAndVerifySignedAddress(stub, principalAddressEncoded)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	// retrieving right
	addressesCompositeKey, err := stub.CreateCompositeKey(holderAddressesKey, []string{channelName, chaincodeName, holderAddress.String()})
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	rawAddresses, err := stub.GetState(addressesCompositeKey)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	principalAddresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, principalAddresses); err != nil {
			return nil, fmt.Errorf(err.Error())
		}
	}

	result := &pb.HaveRight{HaveRight: false}
	for _, existedAddr := range principalAddresses.GetAddresses() {
		if existedAddr.AddrString() == principalAddress.AddrString() {
			result.HaveRight = true
			break
		}
	}

	rawResult, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	return rawResult, nil
}

// GetAllAddressesForHolder returns all principal addresses for specified holder
// args[0] -> channelName
// args[1] -> chaincodeName
// args[2] -> holderAddress
func (c *ACL) GetAllAddressesForHolder(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	argsNum := len(args)
	const requiredArgsCount = 3
	if argsNum != requiredArgsCount {
		return nil, fmt.Errorf(errs.ErrArgumentsCount, argsNum,
			"channel name, chaincode name and holder address required")
	}

	if err := c.verifyAccess(stub); err != nil {
		return nil, fmt.Errorf(fmt.Sprintf(errs.ErrUnauthorized+": %s", err.Error()))
	}

	channelName := args[0]
	chaincodeName := args[1]
	holderAddressEncoded := args[2]

	if len(channelName) == 0 {
		return nil, fmt.Errorf(errs.ErrEmptyChannelName)
	}

	if len(chaincodeName) == 0 {
		return nil, fmt.Errorf(errs.ErrEmptyChaincodeName)
	}

	if len(holderAddressEncoded) == 0 {
		return nil, fmt.Errorf(errs.ErrEmptyHolderAddress)
	}

	holderAddress, err := c.retrieveAndVerifySignedAddress(stub, holderAddressEncoded)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	// retrieving addresses
	addressesCompositeKey, err := stub.CreateCompositeKey(holderAddressesKey, []string{channelName, chaincodeName, holderAddress.String()})
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	rawAddresses, err := stub.GetState(addressesCompositeKey)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	principalAddresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		if err = protojson.Unmarshal(rawAddresses, principalAddresses); err != nil {
			return nil, fmt.Errorf(err.Error())
		}
	}

	rawAddresses, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(principalAddresses)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	return rawAddresses, nil
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
