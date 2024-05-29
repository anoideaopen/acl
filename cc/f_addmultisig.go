package cc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"golang.org/x/crypto/sha3"
)

type AddMultisigRequest struct {
	PublicKeys              []PublicKey
	RequiredSignaturesCount uint32
	Signatures              [][]byte
	Message                 string
	MessageWithSignatures   []string
	Nonce                   string
}

func addMultisig(stub shim.ChaincodeStubInterface, request AddMultisigRequest) error {
	const keysSeparator = ""

	var (
		uniqPks                  = make(map[string]struct{})
		keysBytesInOriginalOrder = make([][]byte, len(request.PublicKeys))
		keysBytesSorted          = make([][]byte, len(request.PublicKeys))
	)

	for i, key := range request.PublicKeys {
		if err := checkBlocked(stub, key.InBase58); err != nil {
			return fmt.Errorf("public key %s is in block list: %w", key.InBase58, err)
		}
		if _, ok := uniqPks[key.InBase58]; ok {
			return errors.New("duplicated public keys")
		}
		uniqPks[key.InBase58] = struct{}{}

		keysBytesInOriginalOrder[i] = key.Bytes
		keysBytesSorted[i] = key.Bytes
	}

	sort.Slice(
		keysBytesSorted,
		func(i, j int) bool {
			return bytes.Compare(keysBytesSorted[i], keysBytesSorted[j]) < 0
		},
	)

	hashed := sha3.Sum256(bytes.Join(keysBytesSorted, []byte(keysSeparator)))
	address := base58.CheckEncode(hashed[1:], hashed[0])
	hashedKeysInHex := hex.EncodeToString(hashed[:])

	if err := checkNonce(stub, address, request.Nonce); err != nil {
		return fmt.Errorf("failed checking nonce: %w", err)
	}

	if err := checkSignatures(request.PublicKeys, request.Message, request.Signatures); err != nil {
		return fmt.Errorf("failed checking signatures: %w", err)
	}

	if err := saveSignedAddress(
		stub, &pb.SignedAddress{
			Address: &pb.Address{
				UserID:       "",
				Address:      hashed[:],
				IsIndustrial: false,
				IsMultisig:   true,
			},
			SignedTx: request.MessageWithSignatures,
			SignaturePolicy: &pb.SignaturePolicy{
				N:       request.RequiredSignaturesCount,
				PubKeys: keysBytesInOriginalOrder,
			},
		},
		hashedKeysInHex,
		failIfExists,
	); err != nil {
		return fmt.Errorf("failed saving signed address: %w", err)
	}

	if err := saveMultisigPublicKey(stub, address, hashedKeysInHex); err != nil {
		return fmt.Errorf("failed saving multisig key: %w", err)
	}

	return nil
}

func checkSignatures(keys []PublicKey, message string, signatures [][]byte) error {
	if len(keys) != len(signatures) {
		return errors.New("numbers of keys and signatures are not equal")
	}

	for i, key := range keys {
		if !verifySignatureWithPublicKeyWithType(key.Bytes, key.Type, messageDigest(message), signatures[i]) {
			return fmt.Errorf(
				"the signature %s does not match the public key %s",
				hex.EncodeToString(signatures[i]),
				key.InBase58)
		}
	}

	return nil
}

func addMultisigRequestFromArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
) (AddMultisigRequest, error) {
	const (
		indexKeysCount = iota
		indexNonce
		indexKeysAndSignatures
		minArgsCount = 4
	)

	argsNum := len(args)
	if argsNum < minArgsCount {
		return AddMultisigRequest{},
			fmt.Errorf("incorrect number of arguments: %d, expected at least %d", argsNum, minArgsCount)
	}

	N, err := strconv.Atoi(args[indexKeysCount])
	if err != nil {
		return AddMultisigRequest{}, fmt.Errorf("failed to parse N: %w", err)
	}

	nonce := args[indexNonce]

	keysAndSignatures := args[indexKeysAndSignatures:]
	if len(keysAndSignatures)%2 != 0 {
		return AddMultisigRequest{}, errors.New("counts of keys and signatures are not equal")
	}

	numberOfKeys := len(keysAndSignatures) / 2
	if numberOfKeys < N {
		return AddMultisigRequest{}, fmt.Errorf("N (%d) is greater then M (number of pubKeys, %d)", N, numberOfKeys)
	}

	if err = helpers.CheckKeysArr(keysAndSignatures[:numberOfKeys]); err != nil {
		return AddMultisigRequest{}, fmt.Errorf("failed checking public keys: %w", err)
	}

	publicKeys := make([]PublicKey, numberOfKeys)
	signatures := make([][]byte, numberOfKeys)
	for i := 0; i < numberOfKeys; i++ {
		if publicKeys[i], err = publicKeyFromBase58String(keysAndSignatures[i]); err != nil {
			return AddMultisigRequest{}, fmt.Errorf("failed decoding public key: %w", err)
		}

		if publicKeys[i].Type, err = readPublicKeyType(stub, publicKeys[i].HashInHex); err != nil {
			return AddMultisigRequest{}, fmt.Errorf("failed reading type of a public key: %w", err)
		}

		if signatures[i], err = hex.DecodeString(keysAndSignatures[i+numberOfKeys]); err != nil {
			return AddMultisigRequest{}, fmt.Errorf("failed decodign signatures: %w", err)
		}
	}

	message := multisigMessage(args[:len(args)-numberOfKeys]...)
	return AddMultisigRequest{
		PublicKeys:              publicKeys,
		Signatures:              signatures,
		RequiredSignaturesCount: uint32(N),
		Message:                 message,
		MessageWithSignatures:   append([]string{message}, keysAndSignatures[len(keysAndSignatures)-numberOfKeys:]...),
		Nonce:                   nonce,
	}, nil
}

func multisigMessage(args ...string) string {
	const (
		op               = "addMultisig"
		messageSeparator = ""
	)
	return strings.Join(append([]string{op}, args...), messageSeparator)
}

func messageDigest(message string) []byte {
	digest := sha3.Sum256([]byte(message))
	return digest[:]
}
