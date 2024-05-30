package cc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"golang.org/x/crypto/sha3"
)

// AddMultisig creates multi-signature address which operates when N of M signatures is present
// arg[0] N number of signature policy (number of sufficient signatures), M part is derived from number of public keys
// arg[1] nonce
// args[2:] are the public keys and signatures hex of all participants in the multi-wallet
// and signatures confirming the agreement of all participants with the signature policy
func (c *ACL) AddMultisig(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen
	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	request, err := addMultisigRequestFromArguments(stub, args)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = addMultisig(stub, request); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// AddMultisigWithBase58Signature creates multi-signature address which operates when N of M signatures is present
// args[0] request id
// args[1] chaincodeName acl
// args[2] channelID acl
// args[3] N number of signature policy (number of sufficient signatures), M part is derived from number of public keys
// args[4] nonce
// args[5:] are the public keys and signatures base58 of all participants in the multi-wallet
// and signatures confirming the agreement of all participants with the signature policy
func (c *ACL) AddMultisigWithBase58Signature(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen,gocognit
	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	request, err := addMultisigWithBase58SignaturesRequestFromArguments(stub, args)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = addMultisig(stub, request); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// ChangeMultisigPublicKey changes public key of multisig member
// arg[0] - multisig address (base58check)
// arg[1] - old key (base58)
// arg[2] - new key (base58)
// arg[3] - reason (string)
// arg[4] - reason ID (string)
// arg[5] - nonce
// arg[6:] - public keys and signatures of validators
func (c *ACL) ChangeMultisigPublicKey(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen,gocyclo,gocognit
	argsNum := len(args)
	const minArgsCount = 8
	if argsNum < minArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, old key, new key, reason, reason ID, nonce, public keys, signatures", argsNum))
	}

	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	multisigAddr := args[0]
	oldKey := args[1]
	encodedBase58NewPublicKey := args[2]
	reason := args[3]
	if len(reason) == 0 {
		return shim.Error("reason not provided")
	}
	if len(args[4]) == 0 {
		return shim.Error("reason ID not provided")
	}
	reasonID, err := strconv.ParseInt(args[4], 10, 32)
	if err != nil {
		return shim.Error("failed to convert reason ID to int, err: " + err.Error())
	}

	nonce := args[5]
	pksAndSignatures := args[6:]
	if len(multisigAddr) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}
	if len(oldKey) == 0 {
		return shim.Error("empty old key")
	}
	if len(encodedBase58NewPublicKey) == 0 {
		return shim.Error("empty new key")
	}
	if len(nonce) == 0 {
		return shim.Error("empty nonce")
	}
	if len(pksAndSignatures) == 0 {
		return shim.Error("no public keys and signatures provided")
	}

	pks := pksAndSignatures[:len(pksAndSignatures)/2]
	signatures := pksAndSignatures[len(pksAndSignatures)/2:]

	if err = checkNonce(stub, multisigAddr, nonce); err != nil {
		return shim.Error(err.Error())
	}

	addrToPkCompositeKey, err := compositekey.PublicKey(stub, multisigAddr)
	if err != nil {
		return shim.Error(err.Error())
	}

	// check that we have pub key for such address
	keys, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(keys) == 0 {
		return shim.Error("no public keys for address " + multisigAddr)
	}

	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, string(keys))
	if err != nil {
		return shim.Error(err.Error())
	}

	// get pb.SignedAddress
	signedAddrBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(signedAddrBytes) == 0 {
		return shim.Error("no SignedAddress msg for address " + multisigAddr)
	}
	signedAddr := &pb.SignedAddress{}
	if err = proto.Unmarshal(signedAddrBytes, signedAddr); err != nil {
		return shim.Error(err.Error())
	}

	// update pubKeys list
	var newKeys []string
	for index, pk := range signedAddr.GetSignaturePolicy().GetPubKeys() {
		if base58.Encode(pk) == oldKey {
			decodedPublicKey, err := helpers.DecodeBase58PublicKey(encodedBase58NewPublicKey)
			if err != nil {
				return shim.Error(err.Error())
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
		return shim.Error(err.Error())
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
		return shim.Error(err.Error())
	}

	// del old addr -> pub key mapping
	err = stub.DelState(addrToPkCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}

	addrChangeMsg, err := proto.Marshal(signedAddr)
	if err != nil {
		return shim.Error(err.Error())
	}

	strKeys := strings.Split(newKeysString, "/")
	if err = helpers.CheckKeysArr(strKeys); err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), newKeysString))
	}
	hashedHexKeys, err := helpers.KeyStringToSortedHashedHex(strKeys)
	if err != nil {
		return shim.Error(err.Error())
	}

	// set new key -> pb.SignedAddress mapping
	newPkToAddrCompositeKey, err := compositekey.SignedAddress(stub, hashedHexKeys)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err = stub.PutState(newPkToAddrCompositeKey, addrChangeMsg); err != nil {
		return shim.Error(err.Error())
	}

	// set new address -> key mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(hashedHexKeys)); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}
