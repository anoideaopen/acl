package cc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"golang.org/x/crypto/sha3"
)

// AddMultisig creates multi-signature address which operates when N of M signatures is present
// arg[0] N number of signature policy (number of sufficient signatures), M part is derived from number of public keys
// arg[1] nonce
// args[2:] are the public keys and signatures hex of all participants in the multi-wallet
// and signatures confirming the agreement of all participants with the signature policy
func (c *ACL) AddMultisig(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if err := c.verifyAccess(stub); err != nil {
		return nil, fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := addMultisigRequestFromArguments(stub, args)
	if err != nil {
		return nil, fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = addMultisig(stub, request); err != nil {
		return nil, fmt.Errorf("failed adding multisig: %w", err)
	}

	return nil, nil
}

// AddMultisigWithBase58Signature creates multi-signature address which operates when N of M signatures is present
// args[0] request id
// args[1] chaincodeName acl
// args[2] channelID acl
// args[3] N number of signature policy (number of sufficient signatures), M part is derived from number of public keys
// args[4] nonce
// args[5:] are the public keys and signatures base58 of all participants in the multi-wallet
// and signatures confirming the agreement of all participants with the signature policy
func (c *ACL) AddMultisigWithBase58Signature(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if err := c.verifyAccess(stub); err != nil {
		return nil, fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := addMultisigWithBase58SignaturesRequestFromArguments(stub, args)
	if err != nil {
		return nil, fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = addMultisig(stub, request); err != nil {
		return nil, fmt.Errorf("failed adding multisig: %w", err)
	}

	return nil, nil
}

// ChangeMultisigPublicKey changes public key of multisig member
// arg[0] - multisig address (base58check)
// arg[1] - old key (base58)
// arg[2] - new key (base58)
// arg[3] - reason (string)
// arg[4] - reason ID (string)
// arg[5] - nonce
// arg[6:] - public keys and signatures of validators
func (c *ACL) ChangeMultisigPublicKey(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) { //nolint:funlen,gocyclo,gocognit
	const minArgsCount = 8

	argsNum := len(args)
	if argsNum < minArgsCount {
		return nil, fmt.Errorf("incorrect number of arguments: %d, but this method expects: address, old key, new key, reason, reason ID, nonce, public keys, signatures", argsNum)
	}

	if err := c.verifyAccess(stub); err != nil {
		return nil, fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	multisigAddr := args[0]
	oldKey := args[1]
	encodedBase58NewPublicKey := args[2]
	reason := args[3]
	if len(reason) == 0 {
		return nil, errors.New("reason not provided")
	}
	if len(args[4]) == 0 {
		return nil, errors.New("reason ID not provided")
	}
	reasonID, err := strconv.ParseInt(args[4], base10, bitSize32)
	if err != nil {
		return nil, fmt.Errorf("failed to convert reason ID to int, err: %w", err)
	}

	nonce := args[5]
	pksAndSignatures := args[6:]
	if len(multisigAddr) == 0 {
		return nil, errors.New(errs.ErrEmptyAddress)
	}
	if len(oldKey) == 0 {
		return nil, errors.New("empty old key")
	}
	if len(encodedBase58NewPublicKey) == 0 {
		return nil, errors.New("empty new key")
	}
	if len(nonce) == 0 {
		return nil, errors.New("empty nonce")
	}
	if len(pksAndSignatures) == 0 {
		return nil, errors.New("no public keys and signatures provided")
	}

	pks := pksAndSignatures[:len(pksAndSignatures)/2]
	signatures := pksAndSignatures[len(pksAndSignatures)/2:]

	if err = checkNonce(stub, multisigAddr, nonce); err != nil {
		return nil, fmt.Errorf("failed checking nonce: %w", err)
	}

	addrToPkCompositeKey, err := compositekey.PublicKey(stub, multisigAddr)
	if err != nil {
		return nil, fmt.Errorf("failed getting public key composite key: %w", err)
	}

	// check that we have pub key for such address
	keys, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return nil, fmt.Errorf("failed getting keys from state: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no public keys for address %s", multisigAddr)
	}

	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, string(keys))
	if err != nil {
		return nil, fmt.Errorf("failed getting signed address composite key: %w", err)
	}

	// get pb.SignedAddress
	signedAddrBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return nil, fmt.Errorf("failed getting signed address from state: %w", err)
	}
	if len(signedAddrBytes) == 0 {
		return nil, fmt.Errorf("no SignedAddress msg for address %s", multisigAddr)
	}
	signedAddr := &pb.SignedAddress{}
	if err = proto.Unmarshal(signedAddrBytes, signedAddr); err != nil {
		return nil, fmt.Errorf("failed unmarshalling signed address: %w", err)
	}

	// update pubKeys list
	var newKeys []string
	for index, pk := range signedAddr.GetSignaturePolicy().GetPubKeys() {
		if base58.Encode(pk) == oldKey {
			decodedPublicKey, err := helpers.DecodeBase58PublicKey(encodedBase58NewPublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed decoding public key: %w", err)
			}
			signedAddr.SignaturePolicy.PubKeys[index] = decodedPublicKey
			newKeys = append(newKeys, encodedBase58NewPublicKey)
		} else {
			newKeys = append(newKeys, base58.Encode(signedAddr.GetSignaturePolicy().GetPubKeys()[index]))
		}
	}

	newKeysString := strings.Join(newKeys, "/")
	message := append([]string{"changeMultisigPublicKey", multisigAddr, oldKey, newKeysString, reason, args[4], nonce}, pks...)
	hashedMessage := sha3.Sum256([]byte(strings.Join(message, "")))
	if err = c.verifyValidatorSignatures(hashedMessage[:], pks, signatures); err != nil {
		return nil, fmt.Errorf("failed verifying signatures: %w", err)
	}

	// ReplaceKeysSignedTx contains strings array ["changeMultisigPublicKey", multisig address, old pk (base58), new pub keys of multisig members (base58), nonce, validators public keys, validators signatures]
	message = append(message, signatures...)
	signedAddr.SignaturePolicy.ReplaceKeysSignedTx = message

	// add reason
	signedAddr.Reason = reason
	signedAddr.ReasonId = int32(reasonID)

	// and delete
	err = stub.DelState(pkToAddrCompositeKey)
	if err != nil {
		return nil, fmt.Errorf("failed deleting signed address from state: %w", err)
	}

	// del old addr -> pub key mapping
	err = stub.DelState(addrToPkCompositeKey)
	if err != nil {
		return nil, fmt.Errorf("failed deleting public key from state: %w", err)
	}

	addrChangeMsg, err := proto.Marshal(signedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling signed address: %w", err)
	}

	strKeys := strings.Split(newKeysString, "/")
	if err = helpers.CheckKeysArr(strKeys); err != nil {
		return nil, fmt.Errorf("failed checking keys array: %w", err)
	}
	hashedHexKeys, err := helpers.KeyStringToSortedHashedHex(strKeys)
	if err != nil {
		return nil, fmt.Errorf("failed converting keys to hex: %w", err)
	}

	// set new key -> pb.SignedAddress mapping
	newPkToAddrCompositeKey, err := compositekey.SignedAddress(stub, hashedHexKeys)
	if err != nil {
		return nil, fmt.Errorf("failed getting signed address composite key: %w", err)
	}
	if err = stub.PutState(newPkToAddrCompositeKey, addrChangeMsg); err != nil {
		return nil, fmt.Errorf("failed putting signed address to state: %w", err)
	}

	// set new address -> key mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(hashedHexKeys)); err != nil {
		return nil, fmt.Errorf("failed putting public keys to state: %w", err)
	}

	return nil, nil
}
