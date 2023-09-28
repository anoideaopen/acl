package cc

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

// decodeBase58PublicKey decode public key from base58 to ed25519 byte array
func decodeBase58PublicKey(encodedBase58PublicKey string) ([]byte, error) {
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

func checkKeysArr(keysArr []string) error {
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

// checkDuplicates checks string array for duplicates and returns duplicates if exists.
func checkDuplicates(arr []string) (duplicateBuffer []string) {
	itemsMap := make(map[string]struct{})
	for _, item := range arr {
		if _, ok := itemsMap[item]; ok {
			if !stringSliceContains(duplicateBuffer, item) {
				duplicateBuffer = append(duplicateBuffer, item)
			}
		} else {
			itemsMap[item] = struct{}{}
		}
	}
	return
}

func stringSliceContains(arr []string, item string) bool {
	for _, found := range arr {
		if item == found {
			return true
		}
	}
	return false
}

func toLowerFirstLetter(in string) string {
	return string(unicode.ToLower(rune(in[0]))) + in[1:]
}

func keyStringToSortedHashedHex(keys []string) (string, error) {
	binKeys := make([][]byte, len(keys))
	for i, encodedBase58PublicKey := range keys {
		publicKey, err := decodeBase58PublicKey(encodedBase58PublicKey)
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

// DecodeAndSort decodes base58 public keys and sorts them
func DecodeAndSort(item string) ([][]byte, error) {
	const delimiter = "/"
	publicKeys := strings.Split(item, delimiter)
	binKeys := make([][]byte, len(publicKeys))
	for i, encodedBase58PublicKey := range publicKeys {
		decodedPublicKey, err := decodeBase58PublicKey(encodedBase58PublicKey)
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

// parseCCName get chaincode name from proposal
func parseCCName(stub shim.ChaincodeStubInterface) (string, error) {
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

// checkPublicKey verify public key in the address variable
func checkPublicKey(address string) error {
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
