package helpers

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

// DecodeBase58PublicKey decode public key from base58 to ed25519 byte array
func DecodeBase58PublicKey(encodedBase58PublicKey string) ([]byte, error) {
	if len(encodedBase58PublicKey) == 0 {
		return nil, errors.New("encoded base 58 public key is empty")
	}
	decode := base58.Decode(encodedBase58PublicKey)
	if len(decode) == 0 {
		return nil, fmt.Errorf("failed base58 decoding of key %s", encodedBase58PublicKey)
	}
	if len(decode) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("incorrect decoded from base58 public key len '%s'. "+
			"decoded public key len is %d but expected %d", encodedBase58PublicKey, len(decode), ed25519.PublicKeySize)
	}
	return decode, nil
}

// IsValidator checks whether a public key belongs to authorized entities and returns true or false
func IsValidator(authorities []string, pk string) bool {
	// check it was a validator
	for _, authorityPublicKey := range authorities {
		if authorityPublicKey == pk {
			return true
		}
	}
	return false
}

// CheckKeysArr checks keys if not empty or having duplicates
func CheckKeysArr(keysArr []string) error {
	uniqPks := make(map[string]struct{})
	for _, p := range keysArr {
		if p == "" {
			return fmt.Errorf("empty public key detected")
		}
		if _, ok := uniqPks[p]; ok {
			return fmt.Errorf("duplicated public keys")
		}
		uniqPks[p] = struct{}{}
	}
	return nil
}

// CheckDuplicates checks a string array for duplicates.
// It returns an error if duplicates are found, indicating the first duplicated item encountered.
func CheckDuplicates(arr []string) error {
	// itemsMap stores unique items encountered so far.
	itemsMap := make(map[string]struct{})

	for _, item := range arr {
		// If the item is already present in the map, return an error indicating duplication.
		if _, ok := itemsMap[item]; ok {
			return fmt.Errorf("found duplicated iteam '%s'", item)
		}

		// Store the item in the map to mark its presence.
		itemsMap[item] = struct{}{}
	}

	// No duplicates found, return nil.
	return nil
}

func stringSliceContains(arr []string, item string) bool { //nolint:unused
	for _, found := range arr {
		if item == found {
			return true
		}
	}
	return false
}

// ToLowerFirstLetter returns string with first letter in lower case
func ToLowerFirstLetter(in string) string {
	return string(unicode.ToLower(rune(in[0]))) + in[1:]
}

// KeyStringToSortedHashedHex returns keys encoded to sorted hashed hex
func KeyStringToSortedHashedHex(keys []string) (string, error) {
	binKeys := make([][]byte, len(keys))
	for i, encodedBase58PublicKey := range keys {
		publicKey, err := DecodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return "", err
		}
		binKeys[i] = publicKey
	}
	sort.Slice(binKeys, func(i, j int) bool {
		return bytes.Compare(binKeys[i], binKeys[j]) < 0
	})
	hashed := sha3.Sum256(bytes.Join(binKeys, []byte("")))
	return hex.EncodeToString(hashed[:]), nil
}

// DecodeAndSort returns decoded and sorted collection
func DecodeAndSort(item string) ([][]byte, error) {
	const delimiter = "/"
	publicKeys := strings.Split(item, delimiter)
	binKeys := make([][]byte, len(publicKeys))
	for i, encodedBase58PublicKey := range publicKeys {
		decodedPublicKey, err := DecodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return nil, err
		}
		binKeys[i] = decodedPublicKey
	}
	sort.Slice(binKeys, func(i, j int) bool {
		return bytes.Compare(binKeys[i], binKeys[j]) < 0
	})
	return binKeys, nil
}

// ParseCCName returns chaincode name from proposal
func ParseCCName(stub shim.ChaincodeStubInterface) (string, error) {
	signedProp, err := stub.GetSignedProposal()
	if err != nil {
		return "", err
	}

	if signedProp == nil {
		return "", fmt.Errorf("failed to get signedProposal, it is nil")
	}

	prop := &peer.Proposal{}
	if err = proto.Unmarshal(signedProp.ProposalBytes, prop); err != nil {
		return "", err
	}

	cpp := &peer.ChaincodeProposalPayload{}
	if err = proto.Unmarshal(prop.Payload, cpp); err != nil {
		return "", err
	}

	cis := &peer.ChaincodeInvocationSpec{}
	if err = proto.Unmarshal(cpp.Input, cis); err != nil {
		return "", err
	}

	// chaincode spec is not set
	if cis.ChaincodeSpec == nil {
		return "", nil
	}

	if cis.ChaincodeSpec.ChaincodeId == nil {
		return "", fmt.Errorf("chaincode ID is not set")
	}

	return cis.ChaincodeSpec.ChaincodeId.Name, nil
}

// CheckPublicKey verifies public key in the address variable
func CheckPublicKey(address string) error {
	result, version, err := base58.CheckDecode(address)
	if err != nil {
		return fmt.Errorf("check decode address : %w", err)
	}

	hash := []byte{version}
	hash = append(hash, result...)

	if len(hash) != ed25519.PublicKeySize {
		return fmt.Errorf("decoded size %d, but must be equal to the length of the ed25519 public key (%d)", len(hash), ed25519.PublicKeySize)
	}

	return nil
}

// MinSignaturesRequired defines the minimum number of signatures required for a multisignature transaction.
const MinSignaturesRequired = 1

// ValidateMinSignatures checks that the number of required signatures is greater than the minimum allowed value.
// It returns an error if the number of required signatures is less than or equal to the minimum allowed value.
func ValidateMinSignatures(n int) error {
	if n <= MinSignaturesRequired {
		return fmt.Errorf("invalid N '%d', must be greater than %d for multisignature transactions", n, MinSignaturesRequired)
	}
	return nil
}