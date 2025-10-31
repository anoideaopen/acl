//nolint:funlen
package cc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha3"
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
	aclproto "github.com/anoideaopen/acl/proto"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

const (
	base10    = 10
	bitSize32 = 32
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
func (c *ACL) AddUser(stub shim.ChaincodeStubInterface, args []string) error {
	const withoutPublicKeyType = false

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := addUserRequestFromArguments(args, withoutPublicKeyType)
	if err != nil {
		return fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = addUser(stub, request); err != nil {
		return fmt.Errorf("failed adding new user: %w", err)
	}

	return nil
}

// AddUserWithPublicKeyType adds user by public key to the ACL
// args is slice of parameters:
// args[0] - encoded base58 user publicKey
// args[1] - Know Your Client (KYC) hash
// args[2] - user identifier
// args[3] - user can do industrial operation or not (boolean)
// args[4] - key type: ed25519, ecdsa, gost
func (c *ACL) AddUserWithPublicKeyType(stub shim.ChaincodeStubInterface, args []string) error {
	const withPublicKeyType = true

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := addUserRequestFromArguments(args, withPublicKeyType)
	if err != nil {
		return fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = addUser(stub, request); err != nil {
		return fmt.Errorf("failed adding new user: %w", err)
	}

	return nil
}

// GetUser returns user by address
// args is slice of parameters:
// args[0] - encoded base58 user address
func (c *ACL) GetUser(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	const argsLen = 1

	if len(args) != argsLen {
		return nil, fmt.Errorf("incorrect number of arguments: expected %d, got %d", argsLen, len(args))
	}

	signedAddress, _, err := c.retrieveSignedAddress(stub, args[0])
	if err != nil {
		return nil, fmt.Errorf("filed retrieving signed address: %w", err)
	}

	marshaledSignedAddress, err := proto.Marshal(signedAddress)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling signed address: %w", err)
	}

	return marshaledSignedAddress, nil
}

// CheckKeys returns AclResponse with account indo fetched by public keys
func (c *ACL) CheckKeys(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	// Attempting to process the request as an additional key. --
	resp, err := c.tryCheckAdditionalKey(stub, args)
	if err != nil {
		return nil, fmt.Errorf("failed checking additional key: %w", err)
	}
	if resp != nil {
		return resp, nil
	}

	request, err := checkKeysRequestFromArguments(args)
	if err != nil {
		return nil, fmt.Errorf("failed parsing arguments: %w", err)
	}

	result, err := checkKeys(stub, request)
	if err != nil {
		return nil, fmt.Errorf("failed checking keys: %w", err)
	}

	marshalled, err := proto.Marshal(&result)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling check keys result: %w", err)
	}

	return marshalled, nil
}

// CheckAddress checks if the address is grayListed
// returns an error if the address is grayListed or returns pb.Address if not
// args[0] - base58-encoded address
func (c *ACL) CheckAddress(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	const argsCount = 1

	argsNum := len(args)
	if argsNum < argsCount {
		return nil, fmt.Errorf("incorrect number of arguments: expected %d, got %d", argsCount, argsNum)
	}

	addrEncoded := args[0]
	if len(addrEncoded) == 0 {
		return nil, errors.New(errs.ErrEmptyAddress)
	}

	signedAddr, err := c.retrieveAndVerifySignedAddress(stub, addrEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving signed address: %w", err)
	}

	// prepare and return pb.Address only (extracted from pb.SignedAddress)
	addrResponse, err := proto.Marshal(signedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling signed address: %w", err)
	}

	return addrResponse, nil
}

// retrieveAndVerifySignedAddress decodes a base58-encoded address and verifies it's not grayListed.
func (c *ACL) retrieveAndVerifySignedAddress(
	stub shim.ChaincodeStubInterface,
	addressBase58Check string,
) (*pb.Address, error) {
	result, _, err := c.retrieveSignedAddress(stub, addressBase58Check)
	if err != nil {
		return nil, err
	}

	return result.GetAddress(), err
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
		return nil, "", errors.New("no such address in the ledger")
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
func (c *ACL) Setkyc(stub shim.ChaincodeStubInterface, args []string) error {
	const argsCount = 5

	argsNum := len(args)
	if argsNum < argsCount {
		return fmt.Errorf("incorrect number of arguments: expected %d, got %d", argsCount, argsNum)
	}

	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	var (
		address             = args[0]
		newKyc              = args[1]
		nonce               = args[2]
		pksAndSignatures    = args[3:]
		lenPksAndSignatures = len(pksAndSignatures)
	)

	if len(address) == 0 {
		return errors.New(errs.ErrEmptyAddress)
	}
	if len(newKyc) == 0 {
		return errors.New("empty KYC hash string")
	}
	if len(nonce) == 0 {
		return errors.New("empty nonce")
	}
	if lenPksAndSignatures == 0 {
		return errors.New("no public keys and signatures provided")
	}
	if lenPksAndSignatures%2 != 0 {
		return fmt.Errorf("uneven number of public keys and signatures provided: %d", lenPksAndSignatures)
	}

	var (
		validatorsCount = lenPksAndSignatures / 2
		pks             = pksAndSignatures[:validatorsCount]
		signatures      = pksAndSignatures[validatorsCount:]
		message         = []byte(strings.Join(append([]string{"setkyc", address, newKyc, nonce}, pks...), ""))
	)

	if err := checkNonce(stub, address, nonce); err != nil {
		return fmt.Errorf("failed checking nonce: %w", err)
	}

	if err := c.verifyValidatorSignatures(message, pks, signatures); err != nil {
		return fmt.Errorf("failed verifying validators signtatures: %w", err)
	}

	cKey, err := compositekey.AccountInfo(stub, address)
	if err != nil {
		return fmt.Errorf("failed creating account info composite key: %w", err)
	}

	infoData, err := checkIfAccountInfoExistsAndGetData(stub, cKey, address)
	if err != nil {
		return fmt.Errorf("failed checking account info: %w", err)
	}

	var info pb.AccountInfo
	if err = proto.Unmarshal(infoData, &info); err != nil {
		return fmt.Errorf("failed unmarshalling account info: %w", err)
	}

	info.KycHash = newKyc

	newAccInfo, err := proto.Marshal(&info)
	if err != nil {
		return fmt.Errorf("failed marshalling account info: %w", err)
	}

	if err = stub.PutState(cKey, newAccInfo); err != nil {
		return fmt.Errorf("failed storing account info: %w", err)
	}

	return nil
}

// GetAddresses reads and returns addresses from state by given page size and bookmark
func (c *ACL) GetAddresses(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	const argsCount = 2

	argsNum := len(args)
	if argsNum != argsCount {
		return nil, fmt.Errorf("incorrect number of arguments: expected %d, got %d", argsCount, argsNum)
	}

	var (
		pageSize = args[0]
		bookmark = args[1]
	)

	pageSizeInt, err := strconv.ParseInt(pageSize, base10, bitSize32)
	if err != nil {
		return nil, fmt.Errorf("failed parsing page size: %w", err)
	}

	if pageSizeInt <= 0 {
		return nil, fmt.Errorf("page size must be greater than zero, current value is '%d'", pageSizeInt)
	}

	iterator, result, err := stub.GetStateByPartialCompositeKeyWithPagination(
		compositekey.PublicKeyPrefix,
		[]string{},
		int32(pageSizeInt),
		bookmark,
	) // we use addr -> pk mapping here
	if err != nil {
		return nil, fmt.Errorf("failed getting state by partial key: %w", err)
	}

	if iterator == nil {
		return nil, errors.New("failed getting state by partial key: empty address iterator")
	}

	defer func() {
		_ = iterator.Close()
	}()

	var addresses []string
	for iterator.HasNext() {
		kv, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed getting next element from iterator: %w", err)
		}
		_, extractedAddr, err := stub.SplitCompositeKey(kv.GetKey())
		if err != nil {
			return nil, fmt.Errorf("failed split composite key: %w", err)
		}
		addresses = append(addresses, extractedAddr[0])
	}

	serialized, err := json.Marshal(AddrsWithPagination{
		Addrs:    addresses,
		Bookmark: result.GetBookmark(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed marshalling addresses: %w", err)
	}

	return serialized, nil
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
func (c *ACL) ChangePublicKeyWithBase58Signature(stub shim.ChaincodeStubInterface, args []string) error {
	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := changePublicKeyRequestWithBase58SignatureFromArguments(stub, args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = c.verifyAllValidatorKeysProvided(request.ValidatorsKeys); err != nil {
		return fmt.Errorf("failed verifying if all validator keys provided: %w", err)
	}

	if err = changePublicKey(stub, request); err != nil {
		return fmt.Errorf("failed changing public key: %w", err)
	}

	return nil
}

// ChangePublicKey changes public key of user
// arg[0] - user's address (base58check)
// arg[1] - reason (string)
// arg[2] - reason ID (string)
// arg[3] - new key (base58)
// arg[4] - nonce
// arg[5:] - public keys and signatures of validators
func (c *ACL) ChangePublicKey(stub shim.ChaincodeStubInterface, args []string) error {
	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := changePublicKeyRequestFromArguments(stub, args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = c.verifyAllValidatorKeysProvided(request.ValidatorsKeys); err != nil {
		return fmt.Errorf("failed verifying if all validator keys provided: %w", err)
	}

	if err = changePublicKey(stub, request); err != nil {
		return fmt.Errorf("failed changing public key: %w", err)
	}

	return nil
}

// ChangePublicKeyWithTypeAndBase58Signature changes public key and its type
// - 0: Request ID
// - 1: Chaincode name
// - 2: Channel ID
// - 3: User's address (base58check)
// - 4: Reason (string)
// - 5: Reason ID (string)
// - 6: New key (base58)
// - 7: New key type
// - 8: Nonce
// - 9 and onwards: List of validators' public keys and their corresponding base58-encoded signatures
func (c *ACL) ChangePublicKeyWithTypeAndBase58Signature(stub shim.ChaincodeStubInterface, args []string) error {
	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := changePublicKeyRequestWithTypeAndBase58SignatureFromArguments(stub, args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = c.verifyAllValidatorKeysProvided(request.ValidatorsKeys); err != nil {
		return fmt.Errorf("failed verifying if all validator keys provided: %w", err)
	}

	if err = changePublicKey(stub, request); err != nil {
		return fmt.Errorf("failed changing public key: %w", err)
	}

	return nil
}

// ChangePublicKeyWithType changes public key and its type
// args[0] - user's address (base58check)
// args[1] - reason (string)
// args[2] - reason ID (string)
// args[3] - new key (base58)
// args[4] - type of the new key
// args[5] - nonce
// args[6:] - public keys and signatures of validators
func (c *ACL) ChangePublicKeyWithType(stub shim.ChaincodeStubInterface, args []string) error {
	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := changePublicKeyRequestWithTypeFromArguments(stub, args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = c.verifyAllValidatorKeysProvided(request.ValidatorsKeys); err != nil {
		return fmt.Errorf("failed verifying if all validator keys provided: %w", err)
	}

	if err = changePublicKey(stub, request); err != nil {
		return fmt.Errorf("failed changing public key: %w", err)
	}

	return nil
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

func (c *ACL) verifyValidatorSignatures(message []byte, validatorKeys, validatorSignatures []string) error {
	if len(validatorSignatures) < len(c.config.GetValidators()) {
		return errors.Errorf("%d of %d signed", len(validatorSignatures), len(c.config.GetValidators()))
	}

	if err := helpers.CheckDuplicates(validatorSignatures); err != nil {
		return fmt.Errorf(errs.ErrDuplicateSignatures, err)
	}
	if err := helpers.CheckDuplicates(validatorKeys); err != nil {
		return fmt.Errorf(errs.ErrDuplicatePubKeys, err)
	}

	validators := make(map[string]*aclproto.ACLValidator)
	for _, validator := range c.config.GetValidators() {
		validators[validator.GetPublicKey()] = validator
	}

	for i, encodedBase58PublicKey := range validatorKeys {
		validator, isValidator := validators[encodedBase58PublicKey]
		if !isValidator {
			return errors.Errorf("pk %s does not belong to any validator", encodedBase58PublicKey)
		}

		// check signature
		decodedSignature, err := hex.DecodeString(validatorSignatures[i])
		if err != nil {
			return err
		}

		ok, err := verifyValidatorSignature(validator, message, decodedSignature)
		if err != nil {
			return fmt.Errorf("failed verifying signature: %w", err)
		}
		if !ok {
			// in this method args signatures in hex
			return errors.Errorf(
				"the signature %s does not match the public key %s",
				validatorSignatures[i],
				encodedBase58PublicKey,
			)
		}
	}
	return nil
}

func (c *ACL) verifyAllValidatorKeysProvided(keys []PublicKey) error {
	var (
		keysCountActual   = len(keys)
		keysCountExpected = len(c.config.GetValidators())
	)

	if keysCountActual != keysCountExpected {
		return errors.Errorf("provided %d validator keys, expected %d", keysCountActual, keysCountExpected)
	}

	allKeys := make(map[string]PublicKey)
	for _, key := range keys {
		allKeys[key.InBase58] = key
	}

	for _, validator := range c.config.GetValidators() {
		_, present := allKeys[validator.GetPublicKey()]
		if !present {
			return errors.New("not all validator keys provided")
		}
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
	b, _ := pem.Decode(sID.GetIdBytes())
	if b == nil {
		return errors.New("no bytes in serialized identity")
	}
	parsed, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}

	pk, ok := parsed.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("bad public key, type conversion of parsed public key failed")
	}

	hash := sha256.New()

	ecdhPk, err := pk.ECDH()
	if err != nil {
		return fmt.Errorf("public key transition failed: %w", err)
	}
	hash.Write(ecdhPk.Bytes())
	hashed := sha3.Sum256(cert)
	if !bytes.Equal(hashed[:], c.adminSKI) &&
		!bytes.Equal(hash.Sum(nil), c.adminSKI) {
		return errors.New(errs.ErrCallerNotAdmin)
	}
	return nil
}
