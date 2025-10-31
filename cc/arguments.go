package cc

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/anoideaopen/acl/helpers"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

const (
	argumentChaincode                  = "chaincode"
	argumentChannel                    = "channel"
	argumentAddress                    = "address"
	argumentNewKey                     = "newKey"
	argumentNewKeyType                 = "newKeyType"
	argumentReason                     = "reason"
	argumentReasonID                   = "reasonID"
	argumentNonce                      = "nonce"
	argumentAdditionalKey              = "additionalKey"
	argumentLabels                     = "labels"
	argumentValidatorKeysAndSignatures = "validatorKeysAndSignatures"
)

const (
	signatureInHex    = false
	signatureInBase58 = true
)

const minPublicKeysAndSignatures = 2

const messageSeparator = ""

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

func parseKeysAndSignatures(
	stub shim.ChaincodeStubInterface,
	keysAndSignatures []string,
	signaturesInBase58 bool,
) ([]PublicKey, [][]byte, error) {
	var err error

	if len(keysAndSignatures)%2 != 0 {
		return []PublicKey{}, [][]byte{}, errors.New("uneven number of public keys and signatures provided")
	}

	numberOfKeys := len(keysAndSignatures) / 2

	if err = helpers.CheckKeysArr(keysAndSignatures[:numberOfKeys]); err != nil {
		return []PublicKey{}, [][]byte{}, fmt.Errorf("failed checking public keys: %w", err)
	}

	keys := make([]PublicKey, numberOfKeys)
	signatures := make([][]byte, numberOfKeys)
	for i := range numberOfKeys {
		if keys[i], err = PublicKeyFromBase58String(keysAndSignatures[i]); err != nil {
			return []PublicKey{}, [][]byte{}, fmt.Errorf("failed decoding public key: %w", err)
		}

		storedType, found, err := readPublicKeyType(stub, keys[i].HashInHex)
		if err != nil {
			return []PublicKey{}, [][]byte{}, fmt.Errorf("failed reading type of a public key: %w", err)
		}
		if found {
			keys[i].Type = storedType
		}

		if signaturesInBase58 {
			signatures[i] = base58.Decode(keysAndSignatures[i+numberOfKeys])
		} else {
			signatures[i], err = hex.DecodeString(keysAndSignatures[i+numberOfKeys])
			if err != nil {
				return []PublicKey{}, [][]byte{}, fmt.Errorf("failed decoding signature: %w", err)
			}
		}
	}

	return keys, signatures, nil
}
