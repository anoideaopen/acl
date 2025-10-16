package cc

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/anoideaopen/acl/cc/compositekey"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"google.golang.org/protobuf/proto"
)

type argumentIndexMatrix map[string]int

func (matrix argumentIndexMatrix) Has(argument string) bool {
	return matrix.IndexOf(argument) > -1
}

func (matrix argumentIndexMatrix) IndexOf(argument string) int {
	if index, ok := matrix[argument]; ok {
		return index
	}
	return -1
}

const (
	argumentChaincode                  = "chaincode"
	argumentChannel                    = "channel"
	argumentAddress                    = "address"
	argumentNewKey                     = "newKey"
	argumentNewKeyType                 = "newKeyType"
	argumentReason                     = "reason"
	argumentReasonID                   = "reasonID"
	argumentNonce                      = "nonce"
	argumentValidatorKeysAndSignatures = "validatorKeysAndSignatures"
)

const (
	signatureInHex    = false
	signatureInBase58 = true
)

func changePublicKeyRequestFromArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
) (ChangePublicKeyRequest, error) {
	const operation = "changePublicKey"

	argsOrder := argumentIndexMatrix{
		argumentAddress:                    0,
		argumentReason:                     1,
		argumentReasonID:                   2,
		argumentNewKey:                     3,
		argumentNonce:                      4,
		argumentValidatorKeysAndSignatures: 5,
	}

	request := ChangePublicKeyRequest{}

	if err := request.parseArguments(stub, args, argsOrder, operation, signatureInHex); err != nil {
		return ChangePublicKeyRequest{}, fmt.Errorf("failed parsing arguments: %w", err)
	}

	return request, nil
}

func changePublicKeyRequestWithTypeFromArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
) (ChangePublicKeyRequest, error) {
	const operation = "changePublicKeyWithType"

	argsOrder := argumentIndexMatrix{
		argumentAddress:                    0,
		argumentReason:                     1,
		argumentReasonID:                   2,
		argumentNewKey:                     3,
		argumentNewKeyType:                 4,
		argumentNonce:                      5,
		argumentValidatorKeysAndSignatures: 6,
	}

	request := ChangePublicKeyRequest{}

	if err := request.parseArguments(stub, args, argsOrder, operation, signatureInHex); err != nil {
		return ChangePublicKeyRequest{}, fmt.Errorf("failed parsing arguments: %w", err)
	}

	return request, nil
}

func changePublicKeyRequestWithBase58SignatureFromArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
) (ChangePublicKeyRequest, error) {
	const operation = "changePublicKeyWithBase58Signature"

	argsOrder := argumentIndexMatrix{
		argumentChaincode:                  1,
		argumentChannel:                    2,
		argumentAddress:                    3,
		argumentReason:                     4,
		argumentReasonID:                   5,
		argumentNewKey:                     6,
		argumentNonce:                      7,
		argumentValidatorKeysAndSignatures: 8,
	}

	request := ChangePublicKeyRequest{}

	if err := request.parseArguments(stub, args, argsOrder, operation, signatureInBase58); err != nil {
		return ChangePublicKeyRequest{}, fmt.Errorf("failed parsing arguments: %w", err)
	}

	return request, nil
}

func changePublicKeyRequestWithTypeAndBase58SignatureFromArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
) (ChangePublicKeyRequest, error) {
	const operation = "changePublicKeyWithTypeAndBase58Signature"

	argsOrder := argumentIndexMatrix{
		argumentChaincode:                  1,
		argumentChannel:                    2,
		argumentAddress:                    3,
		argumentReason:                     4,
		argumentReasonID:                   5,
		argumentNewKey:                     6,
		argumentNewKeyType:                 7,
		argumentNonce:                      8,
		argumentValidatorKeysAndSignatures: 9,
	}

	request := ChangePublicKeyRequest{}

	if err := request.parseArguments(stub, args, argsOrder, operation, signatureInBase58); err != nil {
		return ChangePublicKeyRequest{}, fmt.Errorf("failed parsing arguments: %w", err)
	}

	return request, nil
}

func changePublicKey(stub shim.ChaincodeStubInterface, request ChangePublicKeyRequest) error {
	addrToPkCompositeKey, err := compositekey.PublicKey(stub, request.Address)
	if err != nil {
		return fmt.Errorf("failed making a public key composite key: %w", err)
	}

	// check that we have public key for such an address
	currentKey, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return fmt.Errorf("failed getting keys from state: %w", err)
	}
	if len(currentKey) == 0 {
		return fmt.Errorf("failed getting keys from state: no public keys for address %s", request.Address)
	}
	if bytes.Equal(currentKey, []byte(request.NewPublicKey.HashInHex)) {
		return errors.New("the new key is equivalent to an existing one")
	}

	pkTypeCompositeKey, err := compositekey.PublicKeyType(stub, string(currentKey))
	if err != nil {
		return fmt.Errorf("failed creating public key type composite key: %w", err)
	}
	if err = stub.DelState(pkTypeCompositeKey); err != nil {
		return fmt.Errorf("failed deleting old public key type from state: %w", err)
	}

	// del old pub key -> pb.Address mapping
	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, string(currentKey))
	if err != nil {
		return fmt.Errorf("failed making signed address composite key: %w", err)
	}
	// firstly, get pb.SignedAddress to re-create it later in new mapping
	signedAddrBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return fmt.Errorf("failed getting signed address from state: %w", err)
	}
	if len(signedAddrBytes) == 0 {
		return errors.New("empty signed address bytes in state")
	}
	signedAddr := &pb.SignedAddress{}
	if err = proto.Unmarshal(signedAddrBytes, signedAddr); err != nil {
		return fmt.Errorf("failed unmarshalling signed address: %w", err)
	}

	// and delete
	err = stub.DelState(pkToAddrCompositeKey)
	if err != nil {
		return fmt.Errorf("failed deleting signed address from state: %w", err)
	}

	// del old addr -> pub key mapping
	err = stub.DelState(addrToPkCompositeKey)
	if err != nil {
		return fmt.Errorf("failed deleting public key from state: %w", err)
	}

	if err = checkNonce(stub, request.Address, request.Nonce); err != nil {
		return fmt.Errorf("failed checking nonce: %w", err)
	}

	if err = checkSignatures(request.ValidatorsKeys, request.Message, request.ValidatorsSignatures); err != nil {
		return fmt.Errorf("failed checking signatures: %w", err)
	}

	signedAddr.SignedTx = request.SignedTx
	signedAddr.Reason = request.Reason
	signedAddr.ReasonId = int32(request.ReasonID)

	if err = saveSignedAddress(stub, signedAddr, request.NewPublicKey.HashInHex, rewriteInExists); err != nil {
		return fmt.Errorf("failed saving signed address: %w", err)
	}

	if err = savePublicKey(stub, request.NewPublicKey, request.Address); err != nil {
		return fmt.Errorf("failed saving new public key: %w", err)
	}

	return nil
}
