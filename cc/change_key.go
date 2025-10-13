package cc

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
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

type argumentIndexesForFunction map[string]argumentIndexMatrix

func (indexes argumentIndexesForFunction) IndexesFor(function string) argumentIndexMatrix {
	if matrix, ok := indexes[function]; ok {
		return matrix
	}
	return map[string]int{}
}

const (
	argumentChaincode                  = "chaincode"
	argumentChannel                    = "channel"
	argumentAddress                    = "address"
	argumentNewKey                     = "newKey"
	argumentReason                     = "reason"
	argumentReasonID                   = "reasonID"
	argumentNonce                      = "nonce"
	argumentValidatorKeysAndSignatures = "validatorKeysAndSignatures"
)

var argumentIndexes = argumentIndexesForFunction{
	"changePublicKey": {
		argumentAddress:                    0,
		argumentReason:                     1,
		argumentReasonID:                   2,
		argumentNewKey:                     3,
		argumentNonce:                      4,
		argumentValidatorKeysAndSignatures: 5,
	},
	"changePublicKeyWithBase58Signature": {
		argumentChaincode:                  1,
		argumentChannel:                    2,
		argumentAddress:                    3,
		argumentReason:                     4,
		argumentReasonID:                   5,
		argumentNewKey:                     6,
		argumentNonce:                      7,
		argumentValidatorKeysAndSignatures: 8,
	},
}

type ChangePublicKeyRequest struct {
	ChaincodeName        string
	ChannelName          string
	Address              string
	Reason               string
	ReasonID             int
	NewPublicKey         string
	Nonce                string
	ValidatorsKeys       []string
	ValidatorsSignatures []string
	originalArguments    []string
	function             string
}

func (request ChangePublicKeyRequest) GetMessageForSign() []byte {
	const argumentsDelimiter = ""
	return []byte(request.function + strings.Join(request.originalArguments[:len(request.originalArguments)-len(request.ValidatorsKeys)], argumentsDelimiter))
}

func (request ChangePublicKeyRequest) GetOriginalArguments() []string {
	return request.originalArguments
}

func changePublicKeyRequestFromArguments(args []string, fn string) (ChangePublicKeyRequest, error) {
	const (
		minPublicKeysAndSignatures = 2
		publicKeyDelimiter         = "/"
	)

	arguments := argumentIndexes.IndexesFor(fn)
	minArgumentsCount := arguments.IndexOf(argumentValidatorKeysAndSignatures) + minPublicKeysAndSignatures

	if len(args) < minArgumentsCount {
		return ChangePublicKeyRequest{}, fmt.Errorf("incorrect number of arguments: expected %d, got %d", minArgumentsCount, len(args))
	}

	var (
		chaincodeName, channelName, address, reason, newKey, nonce string
		reasonID                                                   int64
		err                                                        error
	)

	if arguments.Has(argumentChaincode) {
		chaincodeName = args[arguments[argumentChaincode]]
	}

	if arguments.Has(argumentChannel) {
		channelName = args[arguments[argumentChannel]]
	}

	if arguments.Has(argumentAddress) {
		address = args[arguments[argumentAddress]]
		if len(address) == 0 {
			return ChangePublicKeyRequest{}, fmt.Errorf(errs.ErrEmptyAddress)
		}
	}

	if arguments.Has(argumentReason) {
		reason = args[arguments[argumentReason]]
		if len(reason) == 0 {
			return ChangePublicKeyRequest{}, fmt.Errorf("reason not provided")
		}
	}

	if arguments.Has(argumentReasonID) {
		if len(args[arguments[argumentReasonID]]) == 0 {
			return ChangePublicKeyRequest{}, fmt.Errorf("reason ID not provided")
		}
		reasonID, err = strconv.ParseInt(args[arguments[argumentReasonID]], base10, bitSize32)
		if err != nil {
			return ChangePublicKeyRequest{}, fmt.Errorf("failed parsing reason ID: %w", err)
		}
	}

	if arguments.Has(argumentNewKey) {
		if len(args[arguments[argumentNewKey]]) == 0 {
			return ChangePublicKeyRequest{}, fmt.Errorf("empty new key")
		}
		strKeys := strings.Split(args[arguments[argumentNewKey]], publicKeyDelimiter)
		if err = helpers.CheckKeysArr(strKeys); err != nil {
			return ChangePublicKeyRequest{}, fmt.Errorf("failed checking public keys: %w", err)
		}
		newKey, err = helpers.KeyStringToSortedHashedHex(strKeys)
		if err != nil {
			return ChangePublicKeyRequest{}, fmt.Errorf("failed converting public key into sorted hashed hex: %w", err)
		}
	}

	if arguments.Has(argumentNonce) {
		nonce = args[arguments[argumentNonce]]
		if len(nonce) == 0 {
			return ChangePublicKeyRequest{}, fmt.Errorf("empty nonce")
		}
	}

	pksAndSignatures := args[arguments[argumentValidatorKeysAndSignatures]:]
	lenPksAndSignatures := len(pksAndSignatures)
	if lenPksAndSignatures == 0 {
		return ChangePublicKeyRequest{}, fmt.Errorf("no public keys and signatures provided")
	}

	if lenPksAndSignatures%2 != 0 {
		return ChangePublicKeyRequest{}, fmt.Errorf("uneven number of public keys and signatures provided")
	}

	return ChangePublicKeyRequest{
		ChaincodeName:        chaincodeName,
		ChannelName:          channelName,
		Address:              address,
		Reason:               reason,
		ReasonID:             int(reasonID),
		NewPublicKey:         newKey,
		Nonce:                nonce,
		ValidatorsKeys:       pksAndSignatures[:lenPksAndSignatures/2],
		ValidatorsSignatures: pksAndSignatures[lenPksAndSignatures/2:],
		function:             fn,
		originalArguments:    args,
	}, nil
}

func changePublicKey(stub shim.ChaincodeStubInterface, request ChangePublicKeyRequest) error {
	addrToPkCompositeKey, err := compositekey.PublicKey(stub, request.Address)
	if err != nil {
		return fmt.Errorf("failed making a public key composite key: %w", err)
	}

	// check that we have public key for such an address
	keys, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return fmt.Errorf("failed getting keys from state: %w", err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("failed getting keys from state: no public keys for address %s", request.Address)
	}
	if bytes.Equal(keys, []byte(request.NewPublicKey)) {
		return fmt.Errorf("the new key is equivalent to an existing one")
	}

	// del old pub key -> pb.Address mapping
	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, string(keys))
	if err != nil {
		return fmt.Errorf("failed making signed address composite key: %w", err)
	}
	// firstly, get pb.SignedAddress to re-create it later in new mapping
	signedAddrBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return fmt.Errorf("failed getting signed address from state: %w", err)
	}
	if len(signedAddrBytes) == 0 {
		return fmt.Errorf("empty signed address bytes in state")
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

	// set new key -> pb.SignedAddress mapping
	newPkToAddrCompositeKey, err := compositekey.SignedAddress(stub, request.NewPublicKey)
	if err != nil {
		return fmt.Errorf("failed making new signed address composite key: %w", err)
	}

	signedAddr.SignedTx = append([]string{request.function}, request.GetOriginalArguments()...)
	signedAddr.Reason = request.Reason
	signedAddr.ReasonId = int32(request.ReasonID)
	addrChangeMsg, err := proto.Marshal(signedAddr)
	if err != nil {
		return fmt.Errorf("failed marshalling signed address: %w", err)
	}

	if err = stub.PutState(newPkToAddrCompositeKey, addrChangeMsg); err != nil {
		return fmt.Errorf("failed putting new signed address to state: %w", err)
	}

	// set new address -> key mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(request.NewPublicKey)); err != nil {
		return fmt.Errorf("failed putting new public key to state: %w", err)
	}

	return nil
}
