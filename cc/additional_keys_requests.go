package cc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

type (
	AddAdditionalKeyRequest struct {
		Address              string
		AdditionalKey        PublicKey
		Labels               []string
		Nonce                string
		ValidatorsKeys       []PublicKey
		ValidatorsSignatures [][]byte
		Message              string
		SignedTx             []string
	}

	RemoveAdditionalKeyRequest struct {
		Address              string
		AdditionalKey        PublicKey
		Nonce                string
		ValidatorsKeys       []PublicKey
		ValidatorsSignatures [][]byte
		Message              string
		SignedTx             []string
	}
)

func addAdditionalKeyRequestFromArguments(
	stub shim.ChaincodeStubInterface, args []string,
) (AddAdditionalKeyRequest, error) {
	const operation = "addAdditionalKey"

	argsOrder := argumentIndexMatrix{
		argumentAddress:                    0,
		argumentAdditionalKey:              1,
		argumentLabels:                     2,
		argumentNonce:                      3,
		argumentValidatorKeysAndSignatures: 4,
	}

	request := AddAdditionalKeyRequest{}

	if err := request.parseArguments(stub, args, argsOrder, operation); err != nil {
		return AddAdditionalKeyRequest{}, fmt.Errorf("failed parsing arguments: %w", err)
	}

	return request, nil
}

func removeAdditionalKeyRequestFromArguments(
	stub shim.ChaincodeStubInterface, args []string,
) (RemoveAdditionalKeyRequest, error) {
	const operation = "removeAdditionalKey"

	argsOrder := argumentIndexMatrix{
		argumentAddress:                    0,
		argumentAdditionalKey:              1,
		argumentNonce:                      2,
		argumentValidatorKeysAndSignatures: 3,
	}

	request := RemoveAdditionalKeyRequest{}

	if err := request.parseArguments(stub, args, argsOrder, operation); err != nil {
		return RemoveAdditionalKeyRequest{}, fmt.Errorf("failed parsing arguments: %w", err)
	}

	return request, nil
}

func (request *AddAdditionalKeyRequest) parseArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
	argsOrder argumentIndexMatrix,
	operation string,
) error {
	const minPublicKeysAndSignatures = 2

	if !argsOrder.Has(argumentValidatorKeysAndSignatures) {
		return errors.New("missing argument validator keys and signatures")
	}

	var err error

	minArgumentsCount := argsOrder.IndexOf(argumentValidatorKeysAndSignatures) + minPublicKeysAndSignatures

	if len(args) < minArgumentsCount {
		return fmt.Errorf("incorrect number of arguments: expected %d, got %d", minArgumentsCount, len(args))
	}

	if argsOrder.Has(argumentAddress) {
		request.Address = args[argsOrder[argumentAddress]]
		if len(request.Address) == 0 {
			return errors.New("empty address")
		}
	}

	if len(request.Address) == 0 {
		return errors.New("address is empty")
	}

	if argsOrder.Has(argumentAdditionalKey) {
		if len(args[argsOrder[argumentAdditionalKey]]) == 0 {
			return errors.New("empty new key")
		}
		request.AdditionalKey, err = PublicKeyFromBase58String(args[argsOrder[argumentAdditionalKey]])
		if err != nil {
			return fmt.Errorf("failed parsing new additional key: %w", err)
		}
	}

	if err = request.AdditionalKey.validateLength(); err != nil {
		return fmt.Errorf("invalid additional key: %w", err)
	}

	if argsOrder.Has(argumentLabels) {
		if err = json.Unmarshal([]byte(args[argsOrder[argumentLabels]]), &request.Labels); err != nil {
			return fmt.Errorf("invalid labels format: %w", err)
		}
	}

	if argsOrder.Has(argumentNonce) {
		request.Nonce = args[argsOrder[argumentNonce]]
		if len(request.Nonce) == 0 {
			return errors.New("empty nonce")
		}
	}

	request.ValidatorsKeys, request.ValidatorsSignatures, err = parseKeysAndSignatures(stub, args[argsOrder[argumentValidatorKeysAndSignatures]:], signatureInHex)
	if err != nil {
		return fmt.Errorf("failed parsing validator keys and signatures: %w", err)
	}

	request.Message = strings.Join(append([]string{operation}, args[:len(args)-len(request.ValidatorsKeys)]...), messageSeparator)
	request.SignedTx = append([]string{operation}, args...)

	return nil
}

func (request *RemoveAdditionalKeyRequest) parseArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
	argsOrder argumentIndexMatrix,
	operation string,
) error {
	const minPublicKeysAndSignatures = 2

	if !argsOrder.Has(argumentValidatorKeysAndSignatures) {
		return errors.New("missing argument validator keys and signatures")
	}

	var err error

	minArgumentsCount := argsOrder.IndexOf(argumentValidatorKeysAndSignatures) + minPublicKeysAndSignatures

	if len(args) < minArgumentsCount {
		return fmt.Errorf("incorrect number of arguments: expected %d, got %d", minArgumentsCount, len(args))
	}

	if argsOrder.Has(argumentAddress) {
		request.Address = args[argsOrder[argumentAddress]]
		if len(request.Address) == 0 {
			return errors.New("empty address")
		}
	}

	if len(request.Address) == 0 {
		return errors.New("address is empty")
	}

	if argsOrder.Has(argumentAdditionalKey) {
		if len(args[argsOrder[argumentAdditionalKey]]) == 0 {
			return errors.New("empty new key")
		}
		request.AdditionalKey, err = PublicKeyFromBase58String(args[argsOrder[argumentAdditionalKey]])
		if err != nil {
			return fmt.Errorf("failed parsing new additional key: %w", err)
		}
	}

	if err = request.AdditionalKey.validateLength(); err != nil {
		return fmt.Errorf("invalid additional key: %w", err)
	}

	if argsOrder.Has(argumentNonce) {
		request.Nonce = args[argsOrder[argumentNonce]]
		if len(request.Nonce) == 0 {
			return errors.New("empty nonce")
		}
	}

	request.ValidatorsKeys, request.ValidatorsSignatures, err = parseKeysAndSignatures(stub, args[argsOrder[argumentValidatorKeysAndSignatures]:], signatureInHex)
	if err != nil {
		return fmt.Errorf("failed parsing validator keys and signatures: %w", err)
	}

	request.Message = strings.Join(append([]string{operation}, args[:len(args)-len(request.ValidatorsKeys)]...), messageSeparator)
	request.SignedTx = append([]string{operation}, args...)

	return nil
}
