package cc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"golang.org/x/crypto/sha3"
)

// SetAccountInfo sets account info (KYC hash, grayList and blacklist attributes) for address.
// arg[0] - address
// arg[1] - KYC hash
// arg[2] - is address gray listed? ("true" or "false")
// arg[3] - is address black listed? ("true" or "false")
func (c *ACL) SetAccountInfo(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	addrEncoded := args[0]
	if len(addrEncoded) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}

	_, _, err := base58.CheckDecode(addrEncoded)
	if err != nil {
		return shim.Error(fmt.Sprintf("invalid address, %s", err))
	}
	cKeyInfo, err := compositekey.AccountInfo(stub, addrEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}
	_, err = checkIfAccountInfoExistsAndGetData(stub, cKeyInfo, addrEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}

	kycHash := args[1]

	grayListed := args[2]
	if len(grayListed) == 0 {
		return shim.Error("grayList attribute is not set")
	}

	isGrayListed, err := strconv.ParseBool(grayListed)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed to parse graylist attribute, %s", err))
	}

	blacklisted := args[3]
	if len(blacklisted) == 0 {
		return shim.Error("blacklist attribute is not set")
	}

	isBlacklisted, err := strconv.ParseBool(blacklisted)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed to parse blacklist attribute, %s", err))
	}

	if err = c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	infoMsg, err := proto.Marshal(&pb.AccountInfo{KycHash: kycHash, GrayListed: isGrayListed, BlackListed: isBlacklisted})
	if err != nil {
		return shim.Error(err.Error())
	}

	cKey, err := compositekey.AccountInfo(stub, addrEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}
	if err = stub.PutState(cKey, infoMsg); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// GetAccountInfo returns json-serialized account info (KYC hash, grayList and blacklist attributes) for address.
// arg[0] - address
func (c *ACL) GetAccountInfo(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	addrEncoded := args[0]
	if len(addrEncoded) == 0 {
		return shim.Error(errs.ErrEmptyAddress)
	}
	accInfo, err := getAccountInfo(stub, addrEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}
	accInfoSerialized, err := json.Marshal(accInfo)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(accInfoSerialized)
}

func getAccountInfo(stub shim.ChaincodeStubInterface, address string) (*pb.AccountInfo, error) {
	cKeyInfo, err := compositekey.AccountInfo(stub, address)
	if err != nil {
		return nil, err
	}
	infoData, err := checkIfAccountInfoExistsAndGetData(stub, cKeyInfo, address)
	if err != nil {
		return nil, err
	}

	var info pb.AccountInfo
	if err = proto.Unmarshal(infoData, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// checkBlocked fetch account by public key and check account not in black or gray list
func checkBlocked(stub shim.ChaincodeStubInterface, encodedBase58PublicKey string) error {
	decodedPublicKey, err := helpers.DecodeBase58PublicKey(encodedBase58PublicKey)
	if err != nil {
		return err
	}
	hashed := sha3.Sum256(decodedPublicKey)
	pKeys := hex.EncodeToString(hashed[:])

	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, pKeys)
	if err != nil {
		return err
	}

	keyData, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return err
	}
	if len(keyData) == 0 {
		return errors.New(errs.ErrRecordsNotFound)
	}
	var a pb.SignedAddress
	if err = proto.Unmarshal(keyData, &a); err != nil {
		return err
	}

	var info *pb.AccountInfo
	info, err = getAccountInfo(stub, a.GetAddress().AddrString())
	if err != nil {
		return err
	}

	if info.GetBlackListed() {
		return fmt.Errorf("address %s is blacklisted", a.GetAddress().AddrString())
	}
	if info.GetGrayListed() {
		return fmt.Errorf("address %s is graylisted", a.GetAddress().AddrString())
	}

	return nil
}

func isAccountInfoInBlockedLists(accInfo *pb.AccountInfo) bool {
	if accInfo == nil {
		return false
	}

	if accInfo.GetGrayListed() || accInfo.GetBlackListed() {
		return true
	}

	return false
}

func fetchAccountInfoFromPubKeys(stub shim.ChaincodeStubInterface, pubKeys []string) (*pb.AccountInfo, error) {
	var info *pb.AccountInfo

	pKeys, err := helpers.KeyStringToSortedHashedHex(pubKeys)
	if err != nil {
		return nil, fmt.Errorf("converting keys '%s'to sorted hash failed, err: %w", pubKeys, err)
	}

	addr, err := getAddressByHashedKeys(stub, pKeys)
	if err != nil {
		return nil, err
	}

	info, err = getAccountInfo(stub, addr.GetAddress().AddrString())
	if err != nil {
		return nil, err
	}

	return info, nil
}

func checkIfAccountInfoExistsAndGetData(stub shim.ChaincodeStubInterface, cKeyInfo string, address string) ([]byte, error) {
	infoData, err := stub.GetState(cKeyInfo)
	if err != nil {
		return nil, err
	}

	if len(infoData) == 0 {
		return nil, fmt.Errorf(errs.ErrAccountForAddressIsEmpty, address)
	}

	return infoData, nil
}
