//nolint:funlen,gocyclo,gomnd
package cc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

type AddrsWithPagination struct {
	Addrs    []string
	Bookmark string
}

// AddUser adds user by public key to the ACL
// args is slice of parameters:
// args[0] - encoded base58 user publicKey
// args[1] - Know Your Client (KYC) hash
// args[2] - user identifier
// args[3] - user can do industrial operation or not (boolean)
func (c *ACL) AddUser(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const requiredArgsCount = 4
	if argsNum != requiredArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: public key, "+
			"KYC hash, user ID, industrial attribute ('true' or 'false')", argsNum))
	}

	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	encodedBase58PublicKey := args[0]
	kycHash := args[1]
	userID := args[2]
	isIndustrial := args[3] == "true"

	decodedPublicKey, err := helpers.DecodeBase58PublicKey(encodedBase58PublicKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(kycHash) == 0 {
		return shim.Error("empty kyc hash")
	}
	if len(userID) == 0 {
		return shim.Error("empty userID")
	}

	hashed := sha3.Sum256(decodedPublicKey)
	pkeys := hex.EncodeToString(hashed[:])
	addr := base58.CheckEncode(hashed[1:], hashed[0])
	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, pkeys)
	if err != nil {
		return shim.Error(err.Error())
	}

	addrAlreadyInLedgerBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(addrAlreadyInLedgerBytes) != 0 {
		addrAlreadyInLedger := &pb.SignedAddress{}
		err = proto.Unmarshal(addrAlreadyInLedgerBytes, addrAlreadyInLedger)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Error(fmt.Sprintf("The address %s associated with key %s already exists", addrAlreadyInLedger.Address.AddrString(), pkeys))
	}

	addrToPkCompositeKey, err := compositekey.PublicKey(stub, addr)
	if err != nil {
		return shim.Error(err.Error())
	}

	addrMsg, err := proto.Marshal(&pb.SignedAddress{Address: &pb.Address{
		UserID:       userID,
		Address:      hashed[:],
		IsIndustrial: isIndustrial,
		IsMultisig:   false,
	}})
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = stub.PutState(pkToAddrCompositeKey, addrMsg); err != nil {
		return shim.Error(err.Error())
	}

	// save address -> pubkey hash mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(pkeys)); err != nil {
		return shim.Error(err.Error())
	}

	infoMsg, err := proto.Marshal(&pb.AccountInfo{KycHash: kycHash})
	if err != nil {
		return shim.Error(err.Error())
	}

	ckey, err := compositekey.AccountInfo(stub, addr)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err = stub.PutState(ckey, infoMsg); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// GetUser returns user by address
// args is slice of parameters:
// args[0] - encoded base58 user address
func (c *ACL) GetUser(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	const argsLen = 1

	if len(args) != argsLen {
		return shim.Error(
			fmt.Sprintf("incorrect number of arguments: expected %d, got %d", argsLen, len(args)),
		)
	}

	signedAddress, _, err := c.retrieveSignedAddress(stub, args[0])
	if err != nil {
		return shim.Error(
			fmt.Sprintf("retrieve signed address: %s", err),
		)
	}

	marshaledSignedAddress, err := proto.Marshal(signedAddress)
	if err != nil {
		return shim.Error(
			fmt.Sprintf("marshal signed address: %s", err),
		)
	}

	return shim.Success(marshaledSignedAddress)
}

// CheckKeys returns AclResponse with account indo fetched by public keys
func (c *ACL) CheckKeys(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	// Attempting to process the request as an additional key. --
	if resp, ok := c.tryCheckAdditionalKey(stub, args); ok {
		return resp
	}
	// -----------------------------------------------------

	argsNum := len(args)
	if argsNum < 1 {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: N pubkeys", argsNum))
	}

	if len(args[0]) == 0 {
		return shim.Error(errs.ErrEmptyPubKey)
	}

	const multiSignSeparator = "/"
	strKeys := strings.Split(args[0], multiSignSeparator)
	if err := helpers.CheckKeysArr(strKeys); err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[0]))
	}
	pkeys, err := helpers.KeyStringToSortedHashedHex(strKeys)
	if err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[0]))
	}

	addr, err := getAddressByHashedKeys(stub, pkeys)
	if err != nil {
		return shim.Error(err.Error())
	}

	var info *pb.AccountInfo
	if len(strKeys) == 1 {
		info, err = fetchAccountInfoFromPubKeys(stub, strKeys)
		if err != nil {
			return shim.Error(err.Error())
		}
	} else {
		// for multi keys
		info = &pb.AccountInfo{}
		for _, key := range strKeys {
			strKeys = strings.Split(key, "/")
			info, err = fetchAccountInfoFromPubKeys(stub, strKeys)
			if err != nil {
				return shim.Error(err.Error())
			}

			if isAccountInfoInBlockedLists(info) {
				// stop handling
				break
			}
		}
	}

	result, err := proto.Marshal(&pb.AclResponse{
		Account: info,
		Address: addr,
	})
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(result)
}

// CheckAddress checks if the address is graylisted
// returns an error if the address is graylisted or returns pb.Address if not
// args[0] - base58-encoded address
func (c *ACL) CheckAddress(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	if argsNum < 1 {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address", argsNum))
	}

	addrEncoded := args[0]
	if len(addrEncoded) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}

	signedAddr, err := c.retrieveAndVerifySignedAddress(stub, addrEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}

	// prepare and return pb.Address only (extracted from pb.SignedAddress)
	addrResponse, err := proto.Marshal(signedAddr)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(addrResponse)
}

// retrieveAndVerifySignedAddress decodes a base58-encoded address and verifies it's not graylisted.
func (c *ACL) retrieveAndVerifySignedAddress(
	stub shim.ChaincodeStubInterface,
	addressBase58Check string,
) (*pb.Address, error) {
	result, _, err := c.retrieveSignedAddress(stub, addressBase58Check)
	if err != nil {
		return nil, err
	}

	return result.Address, err
}

// retrieveSignedAddress retrieves the SignedAddress associated with a base58-encoded address.
func (c *ACL) retrieveSignedAddress(
	stub shim.ChaincodeStubInterface,
	addressBase58Check string,
) (signedAddress *pb.SignedAddress, publicKeyHash string, err error) {
	addressPublicKeyCompositeKey, err := compositekey.PublicKey(stub, addressBase58Check)
	if err != nil {
		return nil, "", err
	}

	// Check if the public key hash exists in the ACL
	rawPublicKeyHash, err := stub.GetState(addressPublicKeyCompositeKey)
	if err != nil {
		return nil, "", err
	}
	if len(rawPublicKeyHash) == 0 {
		return nil, "", fmt.Errorf("no public keys for address %s", addressBase58Check)
	}

	publicKeyHash = string(rawPublicKeyHash)

	if err = verifyAddressNotGrayListed(stub, addressBase58Check); err != nil {
		return nil, "", err
	}

	// Retrieve pb.SignedAddress
	signedAddressCompositeKey, err := compositekey.SignedAddress(stub, publicKeyHash)
	if err != nil {
		return nil, "", err
	}

	signedAddressBytes, err := stub.GetState(signedAddressCompositeKey)
	if err != nil {
		return nil, "", err
	}
	if len(signedAddressBytes) == 0 {
		return nil, "", fmt.Errorf("no such address in the ledger")
	}

	signedAddress = &pb.SignedAddress{}
	if err = proto.Unmarshal(signedAddressBytes, signedAddress); err != nil {
		return nil, "", err
	}

	return signedAddress, publicKeyHash, nil
}

// updateSignedAddress updates the SignedAddress associated with a public key hash.
func (c *ACL) updateSignedAddress(
	stub shim.ChaincodeStubInterface,
	signedAddress *pb.SignedAddress,
	publicKeyHash string,
) error {
	signedAddressCompositeKey, err := compositekey.SignedAddress(stub, publicKeyHash)
	if err != nil {
		return err
	}

	marshaledSignedAddress, err := proto.Marshal(signedAddress)
	if err != nil {
		return err
	}

	// Saves the updated address structure.
	return stub.PutState(signedAddressCompositeKey, marshaledSignedAddress)
}

// Setkyc updates KYC for address
// arg[0] - address
// arg[1] - KYC hash
// arg[2] - nonce
// arg[3:] - public keys and signatures of validators
func (c *ACL) Setkyc(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const minArgsCount = 5
	if argsNum < minArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, nonce, KYC hash, public keys, signatures", argsNum))
	}

	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	if len(args[0]) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}
	if len(args[1]) == 0 {
		return shim.Error("empty KYC hash string")
	}
	if len(args[2]) == 0 {
		return shim.Error("empty nonce")
	}
	if len(args[3:]) == 0 {
		return shim.Error("no public keys and signatures provided")
	}
	address := args[0]
	newKyc := args[1]
	nonce := args[2]
	pksAndSignatures := args[3:]
	lenPksAndSignatures := len(pksAndSignatures)
	if lenPksAndSignatures == 0 {
		return shim.Error("no public keys and signatures provided")
	}
	if lenPksAndSignatures%2 != 0 {
		return shim.Error(fmt.Sprintf("uneven number of public keys and signatures provided: %d", lenPksAndSignatures))
	}
	validatorsCount := lenPksAndSignatures / 2
	pks := pksAndSignatures[:validatorsCount]
	signatures := pksAndSignatures[validatorsCount:]
	message := sha3.Sum256([]byte(strings.Join(append([]string{"setkyc", address, newKyc, nonce}, pks...), "")))

	if err := checkNonce(stub, address, nonce); err != nil {
		return shim.Error(err.Error())
	}

	if len(pks) != len(signatures) {
		return shim.Error(fmt.Sprintf("public key count should match signature count, got %d keys and %d signatures", len(pks), len(signatures)))
	}

	if err := c.verifyValidatorSignatures(message[:], pks, signatures); err != nil {
		return shim.Error(err.Error())
	}
	ckey, err := compositekey.AccountInfo(stub, address)
	if err != nil {
		return shim.Error(err.Error())
	}
	infoData, err := checkIfAccountInfoExistsAndGetData(stub, ckey, address)
	if err != nil {
		return shim.Error(err.Error())
	}

	var info pb.AccountInfo
	if err = proto.Unmarshal(infoData, &info); err != nil {
		return shim.Error(err.Error())
	}

	info.KycHash = newKyc

	newAccInfo, err := proto.Marshal(&info)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = stub.PutState(ckey, newAccInfo); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (c *ACL) GetAddresses(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const requiredArgsCount = 2
	if argsNum != requiredArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: pagesize, bookmark", argsNum))
	}
	pageSize := args[0]
	bookmark := args[1]
	pageSizeInt, err := strconv.ParseInt(pageSize, 10, 32)
	if err != nil {
		return shim.Error(fmt.Sprintf("page size '%s' is not a valid positive integer: %v", pageSize, err))
	}
	if pageSizeInt <= 0 {
		return shim.Error(fmt.Sprintf("page size must be greater than zero, current value is '%s'", pageSize))
	}
	iterator, result, err := stub.GetStateByPartialCompositeKeyWithPagination(compositekey.PublicKeyPrefix, []string{}, int32(pageSizeInt),
		bookmark) // we use addr -> pk mapping here
	if err != nil {
		return shim.Error(err.Error())
	}
	defer func() {
		_ = iterator.Close()
	}()

	var addrs []string
	for iterator.HasNext() {
		kv, err := iterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}
		_, extractedAddr, err := stub.SplitCompositeKey(kv.Key)
		if err != nil {
			return shim.Error(err.Error())
		}
		addrs = append(addrs, extractedAddr[0])
	}

	serialized, err := json.Marshal(AddrsWithPagination{
		Addrs:    addrs,
		Bookmark: result.Bookmark,
	})
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(serialized)
}

// ChangePublicKeyWithBase58Signature changes the public key of a user with base58 encoding.
// It expects the following arguments:
// - 0: Request ID
// - 1: Chaincode name
// - 2: Channel ID
// - 3: User's address (base58check)
// - 4: Reason (string)
// - 5: Reason ID (string)
// - 6: New key (base58)
// - 7: Nonce
// - 8 and onwards: List of validators' public keys and their corresponding signatures
func (c *ACL) ChangePublicKeyWithBase58Signature(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:gocognit
	argsNum := len(args)
	const minArgsCount = 10
	const chaincodeName = "acl"
	if argsNum < minArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, reason, reason ID, new key, nonce, public keys, signatures", argsNum))
	}

	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	// args[0] is request id
	// requestId := args[0]

	chaincodeNameFromArgs := args[1]
	if chaincodeNameFromArgs != chaincodeName {
		return shim.Error("incorrect chaincode name")
	}

	channelID := args[2]
	if channelID != stub.GetChannelID() {
		return shim.Error("incorrect channel")
	}

	forAddrOrig := args[3]
	if len(forAddrOrig) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}
	err := helpers.CheckPublicKey(forAddrOrig)
	if err != nil {
		return shim.Error(fmt.Sprintf("the user's address is not valid: %s", err.Error()))
	}

	reason := args[4]
	if len(reason) == 0 {
		return shim.Error("reason not provided")
	}

	if len(args[5]) == 0 {
		return shim.Error("reason ID not provided")
	}
	reasonID, err := strconv.ParseInt(args[5], 10, 32)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed to convert reason ID to int, err: %s", err.Error()))
	}

	if len(args[6]) == 0 {
		return shim.Error("empty new key")
	}

	strKeys := strings.Split(args[6], "/")
	if err = helpers.CheckKeysArr(strKeys); err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}
	newkey, err := helpers.KeyStringToSortedHashedHex(strKeys)
	if err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}

	nonce := args[7]
	if len(nonce) == 0 {
		return shim.Error("empty nonce")
	}

	pksAndSignatures := args[8:]
	lenPksAndSignatures := len(pksAndSignatures)
	if lenPksAndSignatures == 0 {
		return shim.Error("no public keys and signatures provided")
	}
	if lenPksAndSignatures%2 != 0 {
		return shim.Error(fmt.Sprintf("uneven number of public keys and signatures provided: %d", lenPksAndSignatures))
	}
	validatorsCount := lenPksAndSignatures / 2
	pks := pksAndSignatures[:validatorsCount]
	signatures := pksAndSignatures[validatorsCount:]

	fn, _ := stub.GetFunctionAndParameters()
	message := sha3.Sum256([]byte(fn + strings.Join(args[:8+validatorsCount], "")))

	if err = checkNonce(stub, forAddrOrig, nonce); err != nil {
		return shim.Error(err.Error())
	}

	if len(pks) != len(signatures) {
		return shim.Error(fmt.Sprintf("public key count should match signature count, got %d keys and %d signatures", len(pks), len(signatures)))
	}

	if err = c.checkValidatorsSignedWithBase58Signature(message[:], pks, signatures); err != nil {
		return shim.Error(err.Error())
	}

	addrToPkCompositeKey, err := compositekey.PublicKey(stub, forAddrOrig)
	if err != nil {
		return shim.Error(err.Error())
	}

	// check that we have pub key for such address
	keys, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(keys) == 0 {
		return shim.Error(fmt.Sprintf("no public keys for address %s", forAddrOrig))
	}
	if bytes.Equal(keys, []byte(newkey)) {
		return shim.Error("the new key is equivalent to an existing one")
	}

	// del old pub key -> pb.Address mapping
	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, string(keys))
	if err != nil {
		return shim.Error(err.Error())
	}
	// firstly get pb.SignedAddress to re-create it later in new mapping
	signedAddrBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(signedAddrBytes) == 0 {
		return shim.Error(fmt.Sprintf("no SignedAddress msg for address %s", forAddrOrig))
	}
	signedAddr := &pb.SignedAddress{}
	if err = proto.Unmarshal(signedAddrBytes, signedAddr); err != nil {
		return shim.Error(err.Error())
	}

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

	// set new key -> pb.SignedAddress mapping
	newPkToAddrCompositeKey, err := compositekey.SignedAddress(stub, newkey)
	if err != nil {
		return shim.Error(err.Error())
	}

	signedAddr.SignedTx = append(append(append([]string{"changePublicKeyWithBase58Signature"}, args[0:5]...), pks...), signatures...)
	signedAddr.Reason = reason
	signedAddr.ReasonId = int32(reasonID)
	addrChangeMsg, err := proto.Marshal(signedAddr)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = stub.PutState(newPkToAddrCompositeKey, addrChangeMsg); err != nil {
		return shim.Error(err.Error())
	}

	// set new address -> key mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(newkey)); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// ChangePublicKey changes public key of user
// arg[0] - user's address (base58check)
// arg[1] - reason (string)
// arg[2] - reason ID (string)
// arg[3] - new key (base58)
// arg[4] - nonce
// arg[5:] - public keys and signatures of validators
func (c *ACL) ChangePublicKey(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const minArgsCount = 7
	if argsNum < minArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, reason, reason ID, new key, nonce, public keys, signatures", argsNum))
	}

	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	if len(args[0]) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}
	if len(args[1]) == 0 {
		return shim.Error("reason not provided")
	}
	if len(args[2]) == 0 {
		return shim.Error("reason ID not provided")
	}
	if len(args[3]) == 0 {
		return shim.Error("empty new key")
	}
	if len(args[4]) == 0 {
		return shim.Error("empty nonce")
	}
	if len(args[5:]) == 0 {
		return shim.Error("no public keys and signatures provided")
	}

	forAddrOrig := args[0]
	reason := args[1]
	reasonID, err := strconv.ParseInt(args[2], 10, 32)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed to convert reason ID to int, err: %s", err.Error()))
	}

	strKeys := strings.Split(args[3], "/")
	if err = helpers.CheckKeysArr(strKeys); err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}
	newkey, err := helpers.KeyStringToSortedHashedHex(strKeys)
	if err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}

	nonce := args[4]
	pksAndSignatures := args[5:]
	lenPksAndSignatures := len(pksAndSignatures)
	if lenPksAndSignatures == 0 {
		return shim.Error("no public keys and signatures provided")
	}
	if lenPksAndSignatures%2 != 0 {
		return shim.Error(fmt.Sprintf("uneven number of public keys and signatures provided: %d", lenPksAndSignatures))
	}
	validatorsCount := lenPksAndSignatures / 2
	pks := pksAndSignatures[:validatorsCount]
	signatures := pksAndSignatures[validatorsCount:]

	if len(pks) != len(signatures) {
		return shim.Error(fmt.Sprintf("public key count should match signature count, got %d keys and %d signatures", len(pks), len(signatures)))
	}

	message := sha3.Sum256([]byte(strings.Join(append([]string{"changePublicKey", forAddrOrig, reason, args[2], args[3], nonce}, pks...), "")))

	if err = checkNonce(stub, forAddrOrig, nonce); err != nil {
		return shim.Error(err.Error())
	}

	if err = c.verifyValidatorSignatures(message[:], pks, signatures); err != nil {
		return shim.Error(err.Error())
	}

	addrToPkCompositeKey, err := compositekey.PublicKey(stub, forAddrOrig)
	if err != nil {
		return shim.Error(err.Error())
	}

	// check that we have pub key for such address
	keys, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(keys) == 0 {
		return shim.Error(fmt.Sprintf("no public keys for address %s", forAddrOrig))
	}

	// del old pub key -> pb.Address mapping
	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, string(keys))
	if err != nil {
		return shim.Error(err.Error())
	}
	// firstly get pb.SignedAddress to re-create it later in new mapping
	signedAddrBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(signedAddrBytes) == 0 {
		return shim.Error(fmt.Sprintf("no SignedAddress msg for address %s", forAddrOrig))
	}
	signedAddr := &pb.SignedAddress{}
	if err = proto.Unmarshal(signedAddrBytes, signedAddr); err != nil {
		return shim.Error(err.Error())
	}

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

	// set new key -> pb.SignedAddress mapping
	newPkToAddrCompositeKey, err := compositekey.SignedAddress(stub, newkey)
	if err != nil {
		return shim.Error(err.Error())
	}

	signedAddr.SignedTx = append(append(append([]string{"changePublicKey"}, args[0:5]...), pks...), signatures...)
	signedAddr.Reason = reason
	signedAddr.ReasonId = int32(reasonID)
	addrChangeMsg, err := proto.Marshal(signedAddr)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = stub.PutState(newPkToAddrCompositeKey, addrChangeMsg); err != nil {
		return shim.Error(err.Error())
	}

	// set new address -> key mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(newkey)); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func checkNonce(stub shim.ChaincodeStubInterface, sender, nonceStr string) error {
	key, err := compositekey.Nonce(stub, sender)
	if err != nil {
		return fmt.Errorf("creating composite key for %s and sender %s failed, err: %w",
			compositekey.NoncePrefix, sender, err)
	}

	const base = 10
	nonce, ok := new(big.Int).SetString(nonceStr, base)
	if !ok {
		return fmt.Errorf("incorrect nonce. can't read nonce %s as int", nonceStr)
	}
	data, err := stub.GetState(key)
	if err != nil {
		return err
	}
	existed := new(big.Int).SetBytes(data)
	if existed.Cmp(nonce) >= 0 {
		return fmt.Errorf("incorrect nonce. nonce from args %s less than exists %s", nonce, existed)
	}
	return stub.PutState(key, nonce.Bytes())
}

func (c *ACL) checkValidatorsSignedWithBase58Signature(message []byte, pks, signatures []string) error {
	var countValidatorsSigned int64
	if err := helpers.CheckDuplicates(signatures); err != nil {
		return fmt.Errorf(errs.ErrDuplicateSignatures, err)
	}
	if err := helpers.CheckDuplicates(pks); err != nil {
		return fmt.Errorf(errs.ErrDuplicatePubKeys, err)
	}

	for i, encodedBase58PublicKey := range pks {
		if !helpers.IsValidator(c.init.Validators, encodedBase58PublicKey) {
			return errors.Errorf("pk %s does not belong to any validator", encodedBase58PublicKey)
		}
		countValidatorsSigned++

		// check signature
		decodedSignature := base58.Decode(signatures[i])
		decodedPublicKey, err := helpers.DecodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return err
		}
		if !ed25519.Verify(decodedPublicKey, message, decodedSignature) {
			return errors.Errorf("the signature %s does not match the public key %s", signatures[i], encodedBase58PublicKey)
		}
	}

	if countValidatorsSigned < c.init.ValidatorsCount {
		return errors.Errorf("%d of %d signed", countValidatorsSigned, c.init.ValidatorsCount)
	}
	return nil
}

func (c *ACL) verifyValidatorSignatures(digest []byte, validatorKeys, validatiorSignatures []string) error {
	var countValidatorsSigned int64
	if err := helpers.CheckDuplicates(validatiorSignatures); err != nil {
		return fmt.Errorf(errs.ErrDuplicateSignatures, err)
	}
	if err := helpers.CheckDuplicates(validatorKeys); err != nil {
		return fmt.Errorf(errs.ErrDuplicatePubKeys, err)
	}

	for i, encodedBase58PublicKey := range validatorKeys {
		if !helpers.IsValidator(c.init.Validators, encodedBase58PublicKey) {
			return errors.Errorf("pk %s does not belong to any validator", encodedBase58PublicKey)
		}
		countValidatorsSigned++

		// check signature
		decodedSignature, err := hex.DecodeString(validatiorSignatures[i])
		if err != nil {
			return err
		}
		decodedPublicKey, err := helpers.DecodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return err
		}
		if !ed25519.Verify(decodedPublicKey, digest, decodedSignature) {
			// TODO why signature in error in base58 format?
			// in this method args signatures in hex
			return errors.Errorf("the signature %s does not match the public key %s", base58.Encode(decodedSignature), encodedBase58PublicKey)
		}
	}

	if countValidatorsSigned < c.init.ValidatorsCount {
		return errors.Errorf("%d of %d signed", countValidatorsSigned, c.init.ValidatorsCount)
	}
	return nil
}

func getAddressByHashedKeys(stub shim.ChaincodeStubInterface, keys string) (*pb.SignedAddress, error) {
	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, keys)
	if err != nil {
		return nil, err
	}

	keyData, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return nil, err
	}
	if len(keyData) == 0 {
		return nil, fmt.Errorf("address not found by key [%s,%s]", compositekey.SignedAddressPrefix, keys)
	}
	var a pb.SignedAddress
	if err = proto.Unmarshal(keyData, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func (c *ACL) verifyAccess(stub shim.ChaincodeStubInterface) error {
	cert, err := stub.GetCreator()
	if err != nil {
		return err
	}
	sID := &msp.SerializedIdentity{}
	if err = proto.Unmarshal(cert, sID); err != nil {
		return fmt.Errorf("could not deserialize a SerializedIdentity, err: %w", err)
	}
	b, _ := pem.Decode(sID.IdBytes)
	parsed, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	pk, ok := parsed.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("bad public key, type conversion of parsed public key failed")
	}

	hash := sha256.New()
	hash.Write(elliptic.Marshal(pk.Curve, pk.X, pk.Y))
	hashed := sha3.Sum256(cert)
	if !bytes.Equal(hashed[:], c.init.AdminSKI) &&
		!bytes.Equal(hash.Sum(nil), c.init.AdminSKI) {
		return errors.New(errs.ErrCallerNotAdmin)
	}
	return nil
}
