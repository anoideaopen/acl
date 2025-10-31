package cc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/anoideaopen/acl/helpers"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

type ChangePublicKeyRequest struct {
	ChaincodeName        string
	ChannelName          string
	Address              string
	Reason               string
	ReasonID             int
	NewPublicKey         PublicKey
	Nonce                string
	ValidatorsKeys       []PublicKey
	ValidatorsSignatures [][]byte
	Message              string
	SignedTx             []string
}

func (request *ChangePublicKeyRequest) parseArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
	argsOrder argumentIndexMatrix,
	operation string,
	signaturesInBase58 bool,
) error {
	var err error

	minArgumentsCount := argsOrder.IndexOf(argumentValidatorKeysAndSignatures) + minPublicKeysAndSignatures

	if len(args) < minArgumentsCount {
		return fmt.Errorf("incorrect number of arguments: expected %d, got %d", minArgumentsCount, len(args))
	}

	if argsOrder.Has(argumentChaincode) {
		request.ChaincodeName = args[argsOrder[argumentChaincode]]
	}

	if argsOrder.Has(argumentChannel) {
		request.ChannelName = args[argsOrder[argumentChannel]]
	}

	if argsOrder.Has(argumentAddress) {
		request.Address = args[argsOrder[argumentAddress]]
		if len(request.Address) == 0 {
			return errors.New("empty address")
		}
	}

	if argsOrder.Has(argumentReason) {
		request.Reason = args[argsOrder[argumentReason]]
		if len(request.Reason) == 0 {
			return errors.New("reason not provided")
		}
	}

	if argsOrder.Has(argumentReasonID) {
		if len(args[argsOrder[argumentReasonID]]) == 0 {
			return errors.New("reason ID not provided")
		}
		request.ReasonID, err = strconv.Atoi(args[argsOrder[argumentReasonID]])
		if err != nil {
			return fmt.Errorf("failed parsing reason ID: %w", err)
		}
	}

	if argsOrder.Has(argumentNewKey) {
		if len(args[argsOrder[argumentNewKey]]) == 0 {
			return errors.New("empty new key")
		}
		request.NewPublicKey, err = PublicKeyFromBase58String(args[argsOrder[argumentNewKey]])
		if err != nil {
			return fmt.Errorf("failed parsing new key: %w", err)
		}
	}

	if argsOrder.Has(argumentNewKeyType) {
		if !helpers.ValidatePublicKeyType(args[argsOrder[argumentNewKeyType]]) {
			return fmt.Errorf("invalid public key type: %s", args[argsOrder[argumentNewKeyType]])
		}
		request.NewPublicKey.Type = args[argsOrder[argumentNewKeyType]]
	} else {
		storedType, found, err := readPublicKeyType(stub, request.NewPublicKey.HashInHex)
		if err != nil {
			return fmt.Errorf("failed reading type of a public key: %w", err)
		}
		if found {
			request.NewPublicKey.Type = storedType
		}
	}

	if err = request.NewPublicKey.validateLength(); err != nil {
		return fmt.Errorf("failed validating new key: %w", err)
	}

	if argsOrder.Has(argumentNonce) {
		request.Nonce = args[argsOrder[argumentNonce]]
		if len(request.Nonce) == 0 {
			return errors.New("empty nonce")
		}
	}

	request.ValidatorsKeys, request.ValidatorsSignatures, err = parseKeysAndSignatures(stub, args[argsOrder[argumentValidatorKeysAndSignatures]:], signaturesInBase58)
	if err != nil {
		return fmt.Errorf("failed parsing validator keys and signatures: %w", err)
	}

	request.Message = strings.Join(append([]string{operation}, args[:len(args)-len(request.ValidatorsKeys)]...), messageSeparator)
	request.SignedTx = append([]string{operation}, args...)

	return nil
}
