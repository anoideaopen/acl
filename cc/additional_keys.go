//nolint:funlen
package cc

import (
	"fmt"
	"strings"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"google.golang.org/protobuf/proto"
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
 3. Attempting to validate an additional key, it returns information about the user and the user's address if the key
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
func (c *ACL) AddAdditionalKey(stub shim.ChaincodeStubInterface, args []string) error {
	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := addAdditionalKeyRequestFromArguments(stub, args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = c.addAdditionalKey(stub, request); err != nil {
		return fmt.Errorf("failed adding additional key: %w", err)
	}

	return nil
}

// RemoveAdditionalKey removes the optional key from the user account.
// For cases, when the key is no longer needed or has been compromised.
//
// Call Arguments:
//   - arg[0]  - user address for "linking" the additional key
//   - arg[1]  - additional key in base58 format for deletion from the account
//   - arg[2]  - nonce value in string format
//   - arg[3:] - public keys and validator signatures
func (c *ACL) RemoveAdditionalKey(stub shim.ChaincodeStubInterface, args []string) error {
	if err := c.verifyAccess(stub); err != nil {
		return fmt.Errorf(errs.ErrUnauthorizedMsg, err.Error())
	}

	request, err := removeAdditionalKeyRequestFromArguments(stub, args)
	if err != nil {
		return fmt.Errorf("failed parsing arguments: %w", err)
	}

	if err = c.removeAdditionalKey(stub, request); err != nil {
		return fmt.Errorf("failed adding additional key: %w", err)
	}

	return nil
}

func (c *ACL) tryCheckAdditionalKey(
	stub shim.ChaincodeStubInterface,
	args []string,
) (resp []byte, err error) {
	const (
		argsLen            = 1
		multisignSeparator = "/"
	)

	// Checking that the argument is the only one needed for the extra key case.
	if len(args) != argsLen {
		return resp, err
	}

	// Check if the argument is a multisignature.
	if strings.Count(args[0], multisignSeparator) > 0 {
		return resp, err
	}

	// Query Parameters.
	publicKey, err := PublicKeyFromBase58String(args[0])
	if err != nil {
		return resp, fmt.Errorf("failed parsing public key: %w", err)
	}

	publicKey.setTypeByKeyLength()

	// Attempting to get the user's address by an additional public key.
	parentAddress, _, err := c.retrieveParentAddress(stub, publicKey.InBase58)
	if err != nil {
		return nil, fmt.Errorf("get parent address for %s: %w", publicKey.InBase58, err)
	}

	// If no parent is found, the key is normal and control is passed to the higher handler.
	if parentAddress == "" {
		return resp, err
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
		Account:  accountInfo,
		Address:  signedAddress,
		KeyTypes: []pb.KeyType{pb.KeyType(pb.KeyType_value[publicKey.Type])},
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

func (c *ACL) addAdditionalKey(stub shim.ChaincodeStubInterface, request AddAdditionalKeyRequest) error {
	if err := checkNonce(stub, request.Address, request.Nonce); err != nil {
		return fmt.Errorf("failed checking nonce: %w", err)
	}

	if err := c.verifyAllValidatorKeysProvided(request.ValidatorsKeys); err != nil {
		return fmt.Errorf("failed verifying if all validator keys provided: %w", err)
	}

	if err := checkSignatures(request.ValidatorsKeys, request.Message, request.ValidatorsSignatures); err != nil {
		return fmt.Errorf("failed checking signatures: %w", err)
	}

	// Check for key duplication in the state.
	parentAddress, additionalKeyParentComposite, err := c.retrieveParentAddress(stub, request.AdditionalKey.InBase58)
	if err != nil {
		return fmt.Errorf("get parent address for %s: %w", request.Address, err)
	}

	if parentAddress != "" {
		return fmt.Errorf(
			"additional public key (%s) for %s already added",
			request.AdditionalKey.InBase58,
			request.Address,
		)
	}

	// Load the SignedAddress parent descriptor at the user's address.
	signedAddress, publicKeyHash, err := c.retrieveSignedAddress(stub, request.Address)
	if err != nil {
		return fmt.Errorf("retrieve user address for %s: %w", request.Address, err)
	}

	// Adding a public key to a user.
	signedAddress.AdditionalKeys = append(signedAddress.AdditionalKeys, &pb.AdditionalKey{
		PublicKeyBase58: request.AdditionalKey.InBase58,
		Labels:          request.Labels,
	})

	// Saves the updated parent address structure.
	if err = c.updateSignedAddress(stub, signedAddress, publicKeyHash); err != nil {
		return fmt.Errorf("update user address for %s: %w", request.Address, err)
	}

	// Saves a link to the parent address.
	if err = stub.PutState(additionalKeyParentComposite, []byte(request.Address)); err != nil {
		return fmt.Errorf("put state (parent link address) for %s: %w", request.Address, err)
	}

	return nil
}

func (c *ACL) removeAdditionalKey(stub shim.ChaincodeStubInterface, request RemoveAdditionalKeyRequest) error {
	if err := checkNonce(stub, request.Address, request.Nonce); err != nil {
		return fmt.Errorf("failed checking nonce: %w", err)
	}

	if err := c.verifyAllValidatorKeysProvided(request.ValidatorsKeys); err != nil {
		return fmt.Errorf("failed verifying if all validator keys provided: %w", err)
	}

	if err := checkSignatures(request.ValidatorsKeys, request.Message, request.ValidatorsSignatures); err != nil {
		return fmt.Errorf("failed checking signatures: %w", err)
	}

	parentAddress, additionalKeyParentComposite, err := c.retrieveParentAddress(stub, request.AdditionalKey.InBase58)
	if err != nil {
		return fmt.Errorf("get parent address for %s: %w", request.Address, err)
	}

	if parentAddress == "" {
		return fmt.Errorf(
			"additional public key's (%s) parent %s not found",
			request.AdditionalKey.InBase58,
			request.Address,
		)
	}

	if parentAddress != request.Address {
		return fmt.Errorf(
			"additional public key's parent address %s doesn't match with argument %s",
			parentAddress,
			request.Address,
		)
	}

	// Load the SignedAddress parent descriptor at the user's address.
	signedAddress, publicKeyHash, err := c.retrieveSignedAddress(stub, request.Address)
	if err != nil {
		return fmt.Errorf("retrieve user address for %s: %w", request.Address, err)
	}

	// Deleting a user's public key.
	additionalKeys := make([]*pb.AdditionalKey, 0, len(signedAddress.GetAdditionalKeys()))
	for _, additionalKey := range signedAddress.GetAdditionalKeys() {
		if additionalKey.GetPublicKeyBase58() == request.AdditionalKey.InBase58 {
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
		return fmt.Errorf("update user address for %s: %w", request.Address, err)
	}

	// Removing the link to the parent address.
	if err = stub.DelState(additionalKeyParentComposite); err != nil {
		return fmt.Errorf("delete state (parent link address) for %s: %w", request.Address, err)
	}

	return nil
}
