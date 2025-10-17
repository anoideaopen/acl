package cc

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

func addMultisigRequestFromArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
) (AddMultisigRequest, error) {
	const op = "addMultisig"

	argsOrder := []string{
		argKeysRequired,
		argNonce,
		argKeysAndSignatures,
	}

	request := AddMultisigRequest{}

	if err := request.parseArguments(stub, args, argsOrder, op, hexSignatures); err != nil {
		return request, fmt.Errorf("failed parsing arguments: %w", err)
	}

	return request, nil
}

func addMultisigWithBase58SignaturesRequestFromArguments(
	stub shim.ChaincodeStubInterface,
	args []string,
) (AddMultisigRequest, error) {
	const op = "addMultisigWithBase58Signature"

	argsOrder := []string{
		argRequestID,
		argChaincodeID,
		argChannelID,
		argKeysRequired,
		argNonce,
		argKeysAndSignatures,
	}

	request := AddMultisigRequest{}

	if err := request.parseArguments(stub, args, argsOrder, op, base58Signatures); err != nil {
		return request, fmt.Errorf("failed parsing arguments: %w", err)
	}

	return request, nil
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
			SignedTx: request.SignedTx,
			SignaturePolicy: &pb.SignaturePolicy{
				N:       uint32(request.RequiredSignaturesCount),
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
