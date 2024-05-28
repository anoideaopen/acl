package cc

import (
	"fmt"

	"github.com/anoideaopen/acl/cc/compositekey"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

const (
	FailIfExists    = false
	RewriteIfExists = true
)

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

	if rewriteIfExists == FailIfExists && len(addrAlreadyInLedgerBytes) != 0 {
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

func savePublicKey(
	stub shim.ChaincodeStubInterface,
	key PublicKey,
) error {
	addrToPkCompositeKey, err := compositekey.PublicKey(stub, key.HashInBase58Check)
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

	if err = stub.PutState(typeKey, []byte(fmt.Sprintf("%d", key.Type))); err != nil {
		return fmt.Errorf("failed putting public key type into the state: %w", err)
	}

	return nil
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