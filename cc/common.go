package cc

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"google.golang.org/protobuf/proto"
)

const (
	failIfExists    = false
	rewriteInExists = true
)

const newAddress = ""

const ACLChaincodeName = "acl"

func saveSignedAddress(
	stub shim.ChaincodeStubInterface,
	address *pb.SignedAddress,
	publicKeysHashHex string,
	rewriteIfExists bool,
) error {
	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, publicKeysHashHex)
	if err != nil {
		return fmt.Errorf("failed creating signed address composite key: %w", err)
	}

	addrAlreadyInLedgerBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return fmt.Errorf("failed checking if address already exists: %w", err)
	}

	if !rewriteIfExists && len(addrAlreadyInLedgerBytes) != 0 {
		addrAlreadyInLedger := &pb.SignedAddress{}
		err = proto.Unmarshal(addrAlreadyInLedgerBytes, addrAlreadyInLedger)
		if err != nil {
			return fmt.Errorf("failed unmarshalling existing signed address: %w", err)
		}
		return fmt.Errorf(
			"the address %s associated with key %s already exists",
			addrAlreadyInLedger.GetAddress().AddrString(),
			publicKeysHashHex,
		)
	}

	addrMsg, err := proto.Marshal(address)
	if err != nil {
		return fmt.Errorf("failed marshalling signed address: %w", err)
	}

	if err = stub.PutState(pkToAddrCompositeKey, addrMsg); err != nil {
		return fmt.Errorf("failed putting signed address into the state: %w", err)
	}

	return nil
}

func saveMultisigPublicKey(
	stub shim.ChaincodeStubInterface,
	address string,
	keyInHex string,
) error {
	addrToPkCompositeKey, err := compositekey.PublicKey(stub, address)
	if err != nil {
		return fmt.Errorf("failed creating public key composite key: %w", err)
	}

	if err = stub.PutState(addrToPkCompositeKey, []byte(keyInHex)); err != nil {
		return fmt.Errorf("failed putting address into the state: %w", err)
	}

	return nil
}

func savePublicKey(
	stub shim.ChaincodeStubInterface,
	key PublicKey,
	address string,
) error {
	if address == "" {
		address = key.HashInBase58Check
	}
	addrToPkCompositeKey, err := compositekey.PublicKey(stub, address)
	if err != nil {
		return fmt.Errorf("failed creating public key composite key: %w", err)
	}

	if err = stub.PutState(addrToPkCompositeKey, []byte(key.HashInHex)); err != nil {
		return fmt.Errorf("failed putting address into the state: %w", err)
	}

	typeKey, err := compositekey.PublicKeyType(stub, key.HashInHex)
	if err != nil {
		return fmt.Errorf("failed creating public key type composite key: %w", err)
	}

	if err = stub.PutState(typeKey, []byte(key.Type)); err != nil {
		return fmt.Errorf("failed putting public key type into the state: %w", err)
	}

	return nil
}

func readPublicKeyType(
	stub shim.ChaincodeStubInterface,
	keyHashInHex string,
) (string, error) {
	typeCompositeKey, err := compositekey.PublicKeyType(stub, keyHashInHex)
	if err != nil {
		return "", fmt.Errorf("failed creating public key type composite key: %w", err)
	}

	keyTypeBytes, err := stub.GetState(typeCompositeKey)
	if err != nil {
		return "", fmt.Errorf("failed reading public key type from the state: %w", err)
	}

	if len(keyTypeBytes) == 0 {
		return helpers.DefaultPublicKeyType(), nil
	}

	return string(keyTypeBytes), nil
}

func saveAccountInfo(
	stub shim.ChaincodeStubInterface,
	info *pb.AccountInfo,
	publicKeyInBase58Check string,
) error {
	infoMsg, err := proto.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed marshalling account info: %w", err)
	}

	cKey, err := compositekey.AccountInfo(stub, publicKeyInBase58Check)
	if err != nil {
		return fmt.Errorf("failed creating account info composite key: %w", err)
	}

	if err = stub.PutState(cKey, infoMsg); err != nil {
		return fmt.Errorf("failed putting account info into the state: %w", err)
	}

	return nil
}

func checkSignatures(keys []PublicKey, message string, signatures [][]byte) error {
	if len(keys) != len(signatures) {
		return errors.New("numbers of keys and signatures are not equal")
	}

	for i, key := range keys {
		ok, err := key.verifySignature([]byte(message), signatures[i])
		if err != nil {
			return fmt.Errorf("failed verifying signature: %w", err)
		}
		if !ok {
			return fmt.Errorf(
				"the signature %s does not match the public key %s",
				hex.EncodeToString(signatures[i]),
				key.InBase58,
			)
		}
	}
	return nil
}
