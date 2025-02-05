package cc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/anoideaopen/acl/helpers"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

const (
	base58Signatures = true
	hexSignatures    = false
)

func indexOf(arg string, order []string) int {
	for i, name := range order {
		if name == arg {
			return i
		}
	}
	return indexNotFound
}

const indexNotFound = -1

const (
	argRequestID         = "requestID"
	argChaincodeID       = "chaincodeID"
	argChannelID         = "channelID"
	argKeysRequired      = "keysRequired"
	argNonce             = "nonce"
	argKeysAndSignatures = "keysAndSignatures"
)

type AddMultisigRequest struct {
	RequestID               string
	ChaincodeName           string
	ChannelName             string
	PublicKeys              []PublicKey
	RequiredSignaturesCount int
	Signatures              [][]byte
	Message                 string
	SignedTx                []string
	Nonce                   string
}

func (r *AddMultisigRequest) parseArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
	argOrder []string,
	operation string,
	signaturesInBase58 bool,
) error {
	const minSignaturesRequired = 1

	var (
		minArgsCount = len(argOrder) + 1 // +1 because each public keys should have a relative signature
		argsNum      = len(args)
		err          error
	)

	if argsNum < minArgsCount {
		return fmt.Errorf("incorrect number of arguments: %d, expected at least %d", argsNum, minArgsCount)
	}

	if index := indexOf(argRequestID, argOrder); index != indexNotFound {
		r.RequestID = args[index]
	}

	if index := indexOf(argChaincodeID, argOrder); index != indexNotFound {
		r.ChaincodeName = args[index]
		if r.ChaincodeName != ACLChaincodeName {
			return errors.New("incorrect chaincode name")
		}
	}

	if index := indexOf(argChannelID, argOrder); index != indexNotFound {
		r.ChannelName = args[index]
		if r.ChannelName != stub.GetChannelID() {
			return errors.New("incorrect channel")
		}
	}

	if index := indexOf(argKeysRequired, argOrder); index != indexNotFound {
		r.RequiredSignaturesCount, err = strconv.Atoi(args[index])
		if err != nil {
			return fmt.Errorf("failed to parse N: %w", err)
		}
		if r.RequiredSignaturesCount < minSignaturesRequired {
			return fmt.Errorf("not enough signatures required, should be at least %d", minSignaturesRequired)
		}
	}

	if index := indexOf(argNonce, argOrder); index != indexNotFound {
		r.Nonce = args[index]
	}

	if index := indexOf(argKeysAndSignatures, argOrder); index != indexNotFound {
		if err = r.parseKeysAndSignatures(stub, args[index:], signaturesInBase58); err != nil {
			return fmt.Errorf("failed parsing keys and signatures: %w", err)
		}
	}

	r.Message = msgAddMultisigRequest(operation, args[:len(args)-len(r.PublicKeys)]...)
	r.SignedTx = append(
		[]string{operation},
		args...,
	)

	return nil
}

func (r *AddMultisigRequest) parseKeysAndSignatures(
	stub shim.ChaincodeStubInterface,
	keysAndSignatures []string,
	signaturesInBase58 bool,
) error {
	var err error

	if len(keysAndSignatures)%2 != 0 {
		return errors.New("counts of keys and signatures are not equal")
	}

	numberOfKeys := len(keysAndSignatures) / 2
	if numberOfKeys < r.RequiredSignaturesCount {
		return fmt.Errorf(
			"number of pubKeys (%d) is less than required (%d)",
			numberOfKeys,
			r.RequiredSignaturesCount,
		)
	}

	if err = helpers.CheckKeysArr(keysAndSignatures[:numberOfKeys]); err != nil {
		return fmt.Errorf("failed checking public keys: %w", err)
	}

	r.PublicKeys = make([]PublicKey, numberOfKeys)
	r.Signatures = make([][]byte, numberOfKeys)
	for i := 0; i < numberOfKeys; i++ {
		if r.PublicKeys[i], err = publicKeyFromBase58String(keysAndSignatures[i]); err != nil {
			return fmt.Errorf("failed decoding public key: %w", err)
		}

		if r.PublicKeys[i].Type, err = readPublicKeyType(stub, r.PublicKeys[i].HashInHex); err != nil {
			return fmt.Errorf("failed reading type of a public key: %w", err)
		}

		if signaturesInBase58 {
			r.Signatures[i] = base58.Decode(keysAndSignatures[i+numberOfKeys])
		} else {
			if r.Signatures[i], err = hex.DecodeString(keysAndSignatures[i+numberOfKeys]); err != nil {
				return fmt.Errorf("failed decodign signatures: %w", err)
			}
		}
	}
	return nil
}

func msgAddMultisigRequest(op string, args ...string) string {
	const (
		messageSeparator = ""
	)
	return strings.Join(append([]string{op}, args...), messageSeparator)
}
