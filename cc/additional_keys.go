//nolint:funlen
package cc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

/*
Description of storage and handling of additional keys:

Key Storage:
 1. Keys are stored in the Hyperledger Fabric stack using composite keys.
 2. Each additional key is associated with the primary address of the user's account.
 3. Storage is performed in two directions:
    -- 'additional_key_parent' + <additional public key> -> <user address>,
       for reverse lookup of the parent address by the additional key.
 4. Structures are stored in protobuf format to ensure consistency with the rest of the code.

Key handling:
 1. Adding a key involves checking the format of the new key, checking for uniqueness, and
    association with the user's primary address.
 2. Deleting a key requires verifying that the key is actually associated with the given user and removing it
    from all associated structures.
 3. Attempting to validate an additional key returns information about the user and the user's address if the key
    is optional for any account.

Note:
  - Multi-signature mechanisms are not used and validator signatures are checked instead.
  - The tryCheckAdditionalKey method returns data in protobuf format for compatibility with method
    CheckKeys.
*/

// AddAdditionalKey adds a new additional public key to the user account.
// Associates the new key with the "parent" address of the user in the ACL.
//
// Call Arguments:
//   - arg[0]  - user address for linking the additional key
//   - arg[1]  - additional key in base58 format to add to your account
//   - arg[2]  - JSON array of tag strings to the key
//   - arg[3]  - nonce value in string format
//   - arg[4:] - public keys and validator signatures
func (c *ACL) AddAdditionalKey(
	stub shim.ChaincodeStubInterface,
	args []string,
) ([]byte, error) {
	const argsLen = 6

	if len(args) < argsLen {
		return nil, fmt.Errorf("incorrect number of arguments: expected %d, got %d", argsLen, len(args))
	}

	// Request parameters.
	var (
		userAddress         = args[0]
		additionalPublicKey = args[1]
		labels              = args[2]
		nonce               = args[3]
		validatorSignatures = args[4:]
	)

	// Argument checking.
	if userAddress == "" {
		return nil, fmt.Errorf("request validation failed: %s", errs.ErrEmptyAddress)
	}

	if additionalPublicKey == "" {
		return nil, fmt.Errorf("request validation failed: %s", errs.ErrEmptyPubKey)
	}

	var labelsList []string
	if err := json.Unmarshal([]byte(labels), &labelsList); err != nil {
		return nil, fmt.Errorf("request validation failed: invalid labels format: %w", err)
	}

	// Checking the correctness of the additional public key.
	if err := validateKeyFormat(additionalPublicKey); err != nil {
		return nil, fmt.Errorf("validation of additional public key for %s failed: %w", userAddress, err)
	}

	// Verification of access rights.
	if err := c.verifyAccess(stub); err != nil {
		return nil, fmt.Errorf("unauthorized access: %w", err)
	}

	// Nonce check.
	if err := checkNonce(stub, userAddress, nonce); err != nil {
		return nil, fmt.Errorf("failed checking nonce: %w", err)
	}

	// Validation of validator signatures.
	var (
		numSignatures          = len(validatorSignatures) / 2
		validatorKeys          = validatorSignatures[:numSignatures]
		validatorHexSignatures = validatorSignatures[numSignatures:]
	)

	// Composing a message to be signed.
	messageElements := []string{
		"addAdditionalKey",
		userAddress,
		additionalPublicKey,
		labels,
		nonce,
	}
	messageElements = append(messageElements, validatorKeys...)

	// Creating a hash of the message.
	messageToSign := []byte(strings.Join(messageElements, ""))
	messageDigest := sha3.Sum256(messageToSign)

	// Reconciling signatures with the hash of the message.
	if err := c.verifyValidatorSignatures(
		messageDigest[:],
		validatorKeys,
		validatorHexSignatures,
	); err != nil {
		return nil, fmt.Errorf("validation of validator signatures failed: %w", err)
	}

	// Check for key duplication in the state.
	parentAddress, additionalKeyParentComposite, err := c.retrieveParentAddress(stub, additionalPublicKey)
	if err != nil {
		return nil, fmt.Errorf("get parent address for %s: %w", userAddress, err)
	}

	if parentAddress != "" {
		return nil, fmt.Errorf(
			"additional public key (%s) for %s already added",
			additionalPublicKey,
			userAddress,
		)
	}

	// Load the SignedAddress parent descriptor at the user's address.
	signedAddress, publicKeyHash, err := c.retrieveSignedAddress(stub, userAddress)
	if err != nil {
		return nil, fmt.Errorf("retrieve user address for %s: %w", userAddress, err)
	}

	// Adding a public key to a user.
	signedAddress.AdditionalKeys = append(signedAddress.AdditionalKeys, &pb.AdditionalKey{
		PublicKeyBase58: additionalPublicKey,
		Labels:          labelsList,
	})

	// Saves the updated parent address structure.
	if err = c.updateSignedAddress(stub, signedAddress, publicKeyHash); err != nil {
		return nil, fmt.Errorf("update user address for %s: %w", userAddress, err)
	}

	// Saves a link to the parent address.
	if err = stub.PutState(additionalKeyParentComposite, []byte(userAddress)); err != nil {
		return nil, fmt.Errorf("put state (parent link address) for %s: %w", userAddress, err)
	}

	return nil, nil
}

// RemoveAdditionalKey removes the optional key from the user account.
// For cases, when the key is no longer needed or has been compromised.
//
// Call Arguments:
//   - arg[0]  - user address for "linking" the additional key
//   - arg[1]  - additional key in base58 format for deletion from the account
//   - arg[2]  - nonce value in string format
//   - arg[3:] - public keys and validator signatures
func (c *ACL) RemoveAdditionalKey(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	const argsLen = 5

	if len(args) < argsLen {
		return nil, fmt.Errorf("incorrect number of arguments: expected %d, got %d", argsLen, len(args))
	}

	// Request Parameters.
	var (
		userAddress         = args[0]
		additionalPublicKey = args[1]
		nonce               = args[2]
		validatorSignatures = args[3:]
	)

	// Argument Validation.
	if userAddress == "" {
		return nil, fmt.Errorf("request validation failed: %s", errs.ErrEmptyAddress)
	}

	if additionalPublicKey == "" {
		return nil, fmt.Errorf("request validation failed: %s", errs.ErrEmptyPubKey)
	}

	// Checking the validity of the key.
	if err := validateKeyFormat(additionalPublicKey); err != nil {
		return nil, fmt.Errorf("validate additional public key for %s: %w", userAddress, err)
	}

	// Verification of access rights.
	if err := c.verifyAccess(stub); err != nil {
		return nil, fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	// Nonce verification.
	if err := checkNonce(stub, userAddress, nonce); err != nil {
		return nil, fmt.Errorf("failed checking nonce: %w", err)
	}

	// Validation of validator signatures.
	var (
		numSignatures          = len(validatorSignatures) / 2
		validatorKeys          = validatorSignatures[:numSignatures]
		validatorHexSignatures = validatorSignatures[numSignatures:]
	)

	// Composing a message to be signed.
	messageElements := []string{
		"removeAdditionalKey",
		userAddress,
		additionalPublicKey,
		nonce,
	}
	messageElements = append(messageElements, validatorKeys...)

	// Creating a hash of the message.
	messageToSign := []byte(strings.Join(messageElements, ""))
	messageDigest := sha3.Sum256(messageToSign)

	// Reconciling signatures with the hash of the message.
	if err := c.verifyValidatorSignatures(
		messageDigest[:],
		validatorKeys,
		validatorHexSignatures,
	); err != nil {
		return nil, fmt.Errorf("validation of validator signatures failed: %w", err)
	}

	// Check that the public key has a parent that matches the user's address.
	parentAddress, additionalKeyParentComposite, err := c.retrieveParentAddress(stub, additionalPublicKey)
	if err != nil {
		return nil, fmt.Errorf("get parent address for %s: %w", userAddress, err)
	}

	if parentAddress == "" {
		return nil, fmt.Errorf(
			"additional public key's (%s) parent %s not found",
			additionalPublicKey,
			userAddress,
		)
	}

	if parentAddress != userAddress {
		return nil, fmt.Errorf(
			"additional public key's parent address %s doesn't match with argument %s",
			parentAddress,
			userAddress,
		)
	}

	// Load the SignedAddress parent descriptor at the user's address.
	signedAddress, publicKeyHash, err := c.retrieveSignedAddress(stub, userAddress)
	if err != nil {
		return nil, fmt.Errorf("retrieve user address for %s: %w", userAddress, err)
	}

	// Deleting a user's public key.
	additionalKeys := make([]*pb.AdditionalKey, 0, len(signedAddress.GetAdditionalKeys()))
	for _, additionalKey := range signedAddress.GetAdditionalKeys() {
		if additionalKey.GetPublicKeyBase58() == additionalPublicKey {
			continue
		}
		additionalKeys = append(additionalKeys, additionalKey)
	}

	if len(additionalKeys) == 0 {
		signedAddress.AdditionalKeys = nil
	} else {
		signedAddress.AdditionalKeys = additionalKeys
	}

	// Saves the updated parent address structure.
	if err = c.updateSignedAddress(stub, signedAddress, publicKeyHash); err != nil {
		return nil, fmt.Errorf("update user address for %s: %w", userAddress, err)
	}

	// Removing the link to the parent address.
	if err = stub.DelState(additionalKeyParentComposite); err != nil {
		return nil, fmt.Errorf("delete state (parent link address) for %s: %w", userAddress, err)
	}

	return nil, nil
}

func (c *ACL) tryCheckAdditionalKey(
	stub shim.ChaincodeStubInterface,
	args []string,
) ([]byte, error) {
	const (
		argsLen            = 1
		multisignSeparator = "/"
	)

	// Checking that the argument is the only one needed for the extra key case.
	if len(args) != argsLen {
		return nil, nil
	}

	// Query Parameters.
	publicKey := args[0]

	// Check if the argument is a multisignature.
	if strings.Count(publicKey, multisignSeparator) > 0 {
		return nil, nil
	}

	// Attempting to get the user's address by an additional public key.
	parentAddress, _, err := c.retrieveParentAddress(stub, publicKey)
	if err != nil {
		return nil, fmt.Errorf("get parent address for %s: %w", publicKey, err)
	}

	// If no parent is found, the key is normal and control is passed to the higher handler.
	if parentAddress == "" {
		return nil, nil
	}

	// Retrieving information about a user by their additional key.
	signedAddress, _, err := c.retrieveSignedAddress(stub, parentAddress)
	if err != nil {
		return nil, fmt.Errorf("get parent signed address for %s: %w", parentAddress, err)
	}

	accountInfo, err := getAccountInfo(stub, signedAddress.GetAddress().AddrString())
	if err != nil {
		return nil, fmt.Errorf("get account info for %s: %w", parentAddress, err)
	}

	response, err := proto.Marshal(&pb.AclResponse{
		Account: accountInfo,
		Address: signedAddress,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal response for %s: %w", parentAddress, err)
	}

	return response, nil
}

func (c *ACL) retrieveParentAddress(
	stub shim.ChaincodeStubInterface,
	publicKeyBase58 string,
) (parentAddress string, compositeKey string, err error) {
	parentCompositeKey, err := compositekey.AdditionalKeyParent(stub, publicKeyBase58)
	if err != nil {
		return "", "", err
	}

	rawParentAddress, err := stub.GetState(parentCompositeKey)
	if err != nil {
		return "", "", err
	}

	return string(rawParentAddress), parentCompositeKey, nil
}

// validateKeyFormat decode public key from base58 to byte array
func validateKeyFormat(encodedBase58PublicKey string) error {
	if len(encodedBase58PublicKey) == 0 {
		return errors.New("encoded base 58 public key is empty")
	}

	decode := base58.Decode(encodedBase58PublicKey)
	if !helpers.ValidateKeyLength(decode) {
		return fmt.Errorf(
			"incorrect decoded from base58 public key len '%s'. "+
				"decoded public key len is %d",
			encodedBase58PublicKey, len(decode),
		)
	}

	return nil
}
