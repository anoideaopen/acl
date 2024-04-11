package cc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/proto"
	pb "github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

const initStateKey = "__init"

func GetInitArgsFromState(stub shim.ChaincodeStubInterface) (*proto.Args, error) {
	data, err := stub.GetState(initStateKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil //nolint:nilnil
	}
	init := &proto.Args{}

	if err = pb.Unmarshal(data, init); err != nil {
		return nil, err
	}

	return init, nil
}

func getNewInitArgsByChaincodeArgs(stub shim.ChaincodeStubInterface) (*proto.Args, error) {
	args := stub.GetStringArgs()
	const minArgsCount = 2
	if len(args) < minArgsCount {
		return nil, errors.New("arguments should be at least 2")
	}

	adminSKI, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid admin SKI (index of args 0) format found '%s' but expected hex encoded string", args[0])
	}

	validatorsCount, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid validator count (index of args 1) format found '%s' but expected value with type int", args[1])
	}

	ccName, err := helpers.ParseCCName(stub)
	if err != nil {
		return nil, err
	}

	const firstValidatorArgIndex = 2
	lastValidatorArgIndex := firstValidatorArgIndex + validatorsCount

	return &proto.Args{
		AdminSKI:        adminSKI,
		ValidatorsCount: validatorsCount,
		Validators:      args[firstValidatorArgIndex:lastValidatorArgIndex],
		CCName:          ccName,
	}, nil
}

func putInitArgsToState(stub shim.ChaincodeStubInterface, newInitArgs *proto.Args) error {
	if newInitArgs == nil {
		return errors.New("initial arguments can't be nil")
	}

	data, err := pb.Marshal(newInitArgs)
	if err != nil {
		return err
	}

	return stub.PutState(initStateKey, data)
}
