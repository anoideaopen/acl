package cc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	pb "github.com/atomyze-foundation/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

const (
	pkPrefix      = "pk"
	addressPrefix = "address"
	accInfoPrefix = "accountinfo"
	noncePrefix   = "nonce"

	// initStateKey - key for storing settings for chaincode
	initStateKey = "__init"
)

// AddrsWithPagination is a struct for storing address data
type AddrsWithPagination struct {
	Addrs    []string
	Bookmark string
}

// AddUser adds user by public key to the ACL
// args is slice of parameters:
// args[0] - encoded base58 user publicKey
// args[1] - Know Your Client (KYC) hash
// args[2] - user identifier
// args[3] - user can do industrial operation or not (boolean)
func (c *ACL) AddUser(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen
	argsNum := len(args)
	const requiredArgsCount = 4
	if argsNum != requiredArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: public key, "+
			"KYC hash, user ID, industrial attribute ('true' or 'false')", argsNum))
	}

	if err := c.checkCert(stub); err != nil {
		return shim.Error(fmt.Sprintf(ErrUnauthorizedMsg, err.Error()))
	}

	encodedBase58PublicKey := args[0]
	kycHash := args[1]
	userID := args[2]
	isIndustrial := args[3] == "true"

	decodedPublicKey, err := decodeBase58PublicKey(encodedBase58PublicKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(kycHash) == 0 {
		return shim.Error("empty kyc hash")
	}
	if len(userID) == 0 {
		return shim.Error("empty userID")
	}

	hashed := sha3.Sum256(decodedPublicKey)
	pkeys := hex.EncodeToString(hashed[:])
	addr := base58.CheckEncode(hashed[1:], hashed[0])
	pkToAddrCompositeKey, err := stub.CreateCompositeKey(addressPrefix, []string{pkeys})
	if err != nil {
		return shim.Error(err.Error())
	}

	addrAlreadyInLedgerBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(addrAlreadyInLedgerBytes) != 0 {
		addrAlreadyInLedger := &pb.SignedAddress{}
		err = proto.Unmarshal(addrAlreadyInLedgerBytes, addrAlreadyInLedger)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Error(fmt.Sprintf("The address %s associated with key %s already exists", addrAlreadyInLedger.Address.AddrString(), pkeys))
	}

	addrToPkCompositeKey, err := stub.CreateCompositeKey(pkPrefix, []string{addr})
	if err != nil {
		return shim.Error(err.Error())
	}

	addrMsg, err := proto.Marshal(&pb.SignedAddress{Address: &pb.Address{
		UserID:       userID,
		Address:      hashed[:],
		IsIndustrial: isIndustrial,
		IsMultisig:   false,
	}})
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = stub.PutState(pkToAddrCompositeKey, addrMsg); err != nil {
		return shim.Error(err.Error())
	}

	// save address -> pubkey hash mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(pkeys)); err != nil {
		return shim.Error(err.Error())
	}

	infoMsg, err := proto.Marshal(&pb.AccountInfo{KycHash: kycHash})
	if err != nil {
		return shim.Error(err.Error())
	}

	ckey, err := stub.CreateCompositeKey(accInfoPrefix, []string{addr})
	if err != nil {
		return shim.Error(err.Error())
	}
	if err = stub.PutState(ckey, infoMsg); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// CheckKeys returns AclResponse with account indo fetched by public keys
func (c *ACL) CheckKeys(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	if argsNum < 1 {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: N pubkeys", argsNum))
	}

	if len(args[0]) == 0 {
		return shim.Error(ErrEmptyPubKey)
	}

	const multiSignSeparator = "/"
	strKeys := strings.Split(args[0], multiSignSeparator)
	if err := checkKeysArr(strKeys); err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[0]))
	}
	pkeys, err := keyStringToSortedHashedHex(strKeys)
	if err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[0]))
	}

	addr, err := getAddressByHashedKeys(stub, pkeys)
	if err != nil {
		return shim.Error(err.Error())
	}

	var info *pb.AccountInfo
	if len(strKeys) == 1 {
		info, err = fetchAccountInfoFromPubKeys(stub, strKeys)
		if err != nil {
			return shim.Error(err.Error())
		}
	} else {
		// for multi keys
		info = &pb.AccountInfo{}
		for _, key := range strKeys {
			strKeys = strings.Split(key, "/")
			info, err = fetchAccountInfoFromPubKeys(stub, strKeys)
			if err != nil {
				return shim.Error(err.Error())
			}

			if isAccountInfoInBlockedLists(info) {
				// stop handling
				break
			}
		}
	}

	result, err := proto.Marshal(&pb.AclResponse{
		Account: info,
		Address: addr,
	})
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(result)
}

// CheckAddress checks if the address is graylisted
// returns an error if the address is graylisted or returns pb.Address if not
// args[0] - base58-encoded address
func (c *ACL) CheckAddress(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	if argsNum < 1 {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address", argsNum))
	}

	addrEncoded := args[0]
	if len(addrEncoded) == 0 {
		return shim.Error(ErrEmptyAddress)
	}

	signedAddr, err := c.getAddressFromString(stub, addrEncoded)
	if err != nil {
		return shim.Error(err.Error())
	}

	// prepare and return pb.Address only (extracted from pb.SignedAddress)
	addrResponse, err := proto.Marshal(signedAddr)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(addrResponse)
}

func (c *ACL) getAddressFromString(stub shim.ChaincodeStubInterface, addrEncoded string) (*pb.Address, error) {
	var result *pb.Address

	addrToPkCompositeKey, err := stub.CreateCompositeKey(pkPrefix, []string{addrEncoded})
	if err != nil {
		return result, err
	}

	// check the pubkey hash exists in ACL
	keys, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return result, err
	}
	if len(keys) == 0 {
		return result, fmt.Errorf("no pub keys for address %s", addrEncoded)
	}

	if err = checkGrayList(stub, addrEncoded); err != nil {
		return result, err
	}

	// get pb.SignedAddress
	pkToAddrCompositeKey, err := stub.CreateCompositeKey(addressPrefix, []string{string(keys)})
	if err != nil {
		return result, err
	}

	addrProto, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return result, err
	}
	if len(addrProto) == 0 {
		return result, fmt.Errorf("no such address in the ledger")
	}

	signedAddr := &pb.SignedAddress{}
	if err = proto.Unmarshal(addrProto, signedAddr); err != nil {
		return result, err
	}

	return signedAddr.Address, nil
}

// Setkyc updates KYC for address
// arg[0] - address
// arg[1] - KYC hash
// arg[2] - nonce
// arg[3:] - public keys and signatures of validators
func (c *ACL) Setkyc(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen
	argsNum := len(args)
	const minArgsCount = 5
	if argsNum < minArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, nonce, KYC hash, public keys, signatures", argsNum))
	}

	if err := c.checkCert(stub); err != nil {
		return shim.Error(fmt.Sprintf(ErrUnauthorizedMsg, err.Error()))
	}

	if len(args[0]) == 0 {
		return shim.Error("empty address")
	}
	if len(args[1]) == 0 {
		return shim.Error("empty KYC hash string")
	}
	if len(args[2]) == 0 {
		return shim.Error("empty nonce")
	}
	if len(args[3:]) == 0 {
		return shim.Error("no public keys and signatures provided")
	}
	address := args[0]
	newKyc := args[1]
	nonce := args[2]
	PksAndSignatures := args[3:]
	pks := PksAndSignatures[:len(PksAndSignatures)/2]
	signatures := PksAndSignatures[len(PksAndSignatures)/2:]
	message := sha3.Sum256([]byte(strings.Join(append([]string{"setkyc", address, newKyc, nonce}, pks...), "")))

	if err := checkNonce(stub, address, nonce); err != nil {
		return shim.Error(err.Error())
	}

	if err := c.checkValidatorsSigned(message[:], pks, signatures); err != nil {
		return shim.Error(err.Error())
	}
	ckey, err := stub.CreateCompositeKey(accInfoPrefix, []string{address})
	if err != nil {
		return shim.Error(err.Error())
	}
	infoData, err := checkIfAccountInfoExistsAndGetData(stub, ckey, address)
	if err != nil {
		return shim.Error(err.Error())
	}

	var info pb.AccountInfo
	if err = proto.Unmarshal(infoData, &info); err != nil {
		return shim.Error(err.Error())
	}

	info.KycHash = newKyc

	newAccInfo, err := proto.Marshal(&info)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = stub.PutState(ckey, newAccInfo); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// GetAddresses returns json-serialized address data
func (c *ACL) GetAddresses(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	argsNum := len(args)
	const requiredArgsCount = 2
	if argsNum != requiredArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: pagesize, bookmark", argsNum))
	}
	pageSize := args[0]
	bookmark := args[1]
	pageSizeInt, err := strconv.ParseInt(pageSize, 10, 32)
	if err != nil {
		return shim.Error(err.Error())
	}
	iterator, result, err := stub.GetStateByPartialCompositeKeyWithPagination(pkPrefix, []string{}, int32(pageSizeInt),
		bookmark) // we use addr -> pk mapping here
	if err != nil {
		return shim.Error(err.Error())
	}
	defer func() {
		_ = iterator.Close()
	}()

	var addrs []string
	for iterator.HasNext() {
		kv, err := iterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}
		_, extractedAddr, err := stub.SplitCompositeKey(kv.Key)
		if err != nil {
			return shim.Error(err.Error())
		}
		addrs = append(addrs, extractedAddr[0])
	}

	serialized, err := json.Marshal(AddrsWithPagination{
		Addrs:    addrs,
		Bookmark: result.Bookmark,
	})
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(serialized)
}

// ChangePublicKeyWithBase58Signature changes public key of user
// arg[3] - user's address (base58check)
// arg[4] - reason (string)
// arg[5] - reason ID (string)
// arg[6] - new key (base58)
// arg[7] - nonce
// arg[8:] - public keys and signatures of validators
func (c *ACL) ChangePublicKeyWithBase58Signature(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen,gocyclo
	argsNum := len(args)
	const minArgsCount = 10
	const chaincodeName = "acl"
	if argsNum < minArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, reason, reason ID, new key, nonce, public keys, signatures", argsNum))
	}

	if err := c.checkCert(stub); err != nil {
		return shim.Error(fmt.Sprintf(ErrUnauthorizedMsg, err.Error()))
	}

	// args[0] is request id
	// requestId := args[0]

	chaincodeNameFromArgs := args[1]
	if chaincodeNameFromArgs != chaincodeName {
		return shim.Error("incorrect chaincode name")
	}

	channelID := args[2]
	if channelID != stub.GetChannelID() {
		return shim.Error("incorrect channel")
	}

	forAddrOrig := args[3]
	if len(forAddrOrig) == 0 {
		return shim.Error("empty address")
	}
	err := checkPublicKey(forAddrOrig)
	if err != nil {
		return shim.Error(fmt.Sprintf("the user's address is not valid: %s", err.Error()))
	}

	reason := args[4]
	if len(reason) == 0 {
		return shim.Error("reason not provided")
	}

	if len(args[5]) == 0 {
		return shim.Error("reason ID not provided")
	}
	reasonID, err := strconv.ParseInt(args[5], 10, 32)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed to convert reason ID to int, err: %s", err.Error()))
	}

	if len(args[6]) == 0 {
		return shim.Error("empty new key")
	}

	strKeys := strings.Split(args[6], "/")
	if err = checkKeysArr(strKeys); err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}
	newkey, err := keyStringToSortedHashedHex(strKeys)
	if err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}

	nonce := args[7]
	if len(nonce) == 0 {
		return shim.Error("empty nonce")
	}

	pksAndSignatures := args[8:]
	if len(pksAndSignatures) == 0 {
		return shim.Error("no public keys and signatures provided")
	}
	validatorCount := len(pksAndSignatures) / 2 //nolint:gomnd
	pks := pksAndSignatures[:validatorCount]
	signatures := pksAndSignatures[validatorCount:]

	fn, _ := stub.GetFunctionAndParameters()
	message := sha3.Sum256([]byte(fn + strings.Join(args[:8+validatorCount], "")))

	if err = checkNonce(stub, forAddrOrig, nonce); err != nil {
		return shim.Error(err.Error())
	}

	if err = c.checkValidatorsSignedWithBase58Signature(message[:], pks, signatures); err != nil {
		return shim.Error(err.Error())
	}

	addrToPkCompositeKey, err := stub.CreateCompositeKey(pkPrefix, []string{forAddrOrig})
	if err != nil {
		return shim.Error(err.Error())
	}

	// check that we have pub key for such address
	keys, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(keys) == 0 {
		return shim.Error(fmt.Sprintf("no pub keys for address %s", forAddrOrig))
	}
	if bytes.Equal(keys, []byte(newkey)) {
		return shim.Error("the new key is equivalent to an existing one")
	}

	// del old pub key -> pb.Address mapping
	pkToAddrCompositeKey, err := stub.CreateCompositeKey(addressPrefix, []string{string(keys)})
	if err != nil {
		return shim.Error(err.Error())
	}
	// firstly get pb.SignedAddress to re-create it later in new mapping
	signedAddrBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(signedAddrBytes) == 0 {
		return shim.Error(fmt.Sprintf("no SignedAddress msg for address %s", forAddrOrig))
	}
	signedAddr := &pb.SignedAddress{}
	if err = proto.Unmarshal(signedAddrBytes, signedAddr); err != nil {
		return shim.Error(err.Error())
	}

	// and delete
	err = stub.DelState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}

	// del old addr -> pub key mapping
	err = stub.DelState(addrToPkCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}

	// set new key -> pb.SignedAddress mapping
	newPkToAddrCompositeKey, err := stub.CreateCompositeKey(addressPrefix, []string{newkey})
	if err != nil {
		return shim.Error(err.Error())
	}

	signedAddr.SignedTx = append(append(append([]string{"changePublicKeyWithBase58Signature"}, args[0:5]...), pks...), signatures...)
	signedAddr.Reason = reason
	signedAddr.ReasonId = int32(reasonID)
	addrChangeMsg, err := proto.Marshal(signedAddr)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = stub.PutState(newPkToAddrCompositeKey, addrChangeMsg); err != nil {
		return shim.Error(err.Error())
	}

	// set new address -> key mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(newkey)); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// ChangePublicKey changes public key of user
// arg[0] - user's address (base58check)
// arg[1] - reason (string)
// arg[2] - reason ID (string)
// arg[3] - new key (base58)
// arg[4] - nonce
// arg[5:] - public keys and signatures of validators
func (c *ACL) ChangePublicKey(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen
	argsNum := len(args)
	const minArgsCount = 7
	if argsNum < minArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, reason, reason ID, new key, nonce, public keys, signatures", argsNum))
	}

	if err := c.checkCert(stub); err != nil {
		return shim.Error(fmt.Sprintf(ErrUnauthorizedMsg, err.Error()))
	}

	if len(args[0]) == 0 {
		return shim.Error("empty address")
	}
	if len(args[1]) == 0 {
		return shim.Error("reason not provided")
	}
	if len(args[2]) == 0 {
		return shim.Error("reason ID not provided")
	}
	if len(args[3]) == 0 {
		return shim.Error("empty new key")
	}
	if len(args[4]) == 0 {
		return shim.Error("empty nonce")
	}
	if len(args[5:]) == 0 {
		return shim.Error("no public keys and signatures provided")
	}

	forAddrOrig := args[0]
	reason := args[1]
	reasonID, err := strconv.ParseInt(args[2], 10, 32)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed to convert reason ID to int, err: %s", err.Error()))
	}

	strKeys := strings.Split(args[3], "/")
	if err = checkKeysArr(strKeys); err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}
	newkey, err := keyStringToSortedHashedHex(strKeys)
	if err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}

	nonce := args[4]
	PksAndSignatures := args[5:]
	pks := PksAndSignatures[:len(PksAndSignatures)/2]
	signatures := PksAndSignatures[len(PksAndSignatures)/2:]

	// check all members signed
	if len(pks) != len(signatures) {
		return shim.Error(fmt.Sprintf("the number of signatures (%d) does not match the number of public keys (%d)", len(signatures), len(pks)))
	}

	message := sha3.Sum256([]byte(strings.Join(append([]string{"changePublicKey", forAddrOrig, reason, args[2], args[3], nonce}, pks...), "")))

	if err = checkNonce(stub, forAddrOrig, nonce); err != nil {
		return shim.Error(err.Error())
	}

	if err = c.checkValidatorsSigned(message[:], pks, signatures); err != nil {
		return shim.Error(err.Error())
	}

	addrToPkCompositeKey, err := stub.CreateCompositeKey(pkPrefix, []string{forAddrOrig})
	if err != nil {
		return shim.Error(err.Error())
	}

	// check that we have pub key for such address
	keys, err := stub.GetState(addrToPkCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(keys) == 0 {
		return shim.Error(fmt.Sprintf("no pub keys for address %s", forAddrOrig))
	}

	// del old pub key -> pb.Address mapping
	pkToAddrCompositeKey, err := stub.CreateCompositeKey(addressPrefix, []string{string(keys)})
	if err != nil {
		return shim.Error(err.Error())
	}
	// firstly get pb.SignedAddress to re-create it later in new mapping
	signedAddrBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(signedAddrBytes) == 0 {
		return shim.Error(fmt.Sprintf("no SignedAddress msg for address %s", forAddrOrig))
	}
	signedAddr := &pb.SignedAddress{}
	if err = proto.Unmarshal(signedAddrBytes, signedAddr); err != nil {
		return shim.Error(err.Error())
	}

	// and delete
	err = stub.DelState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}

	// del old addr -> pub key mapping
	err = stub.DelState(addrToPkCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}

	// set new key -> pb.SignedAddress mapping
	newPkToAddrCompositeKey, err := stub.CreateCompositeKey(addressPrefix, []string{newkey})
	if err != nil {
		return shim.Error(err.Error())
	}

	signedAddr.SignedTx = append(append(append([]string{"changePublicKey"}, args[0:5]...), pks...), signatures...)
	signedAddr.Reason = reason
	signedAddr.ReasonId = int32(reasonID)
	addrChangeMsg, err := proto.Marshal(signedAddr)
	if err != nil {
		return shim.Error(err.Error())
	}

	if err = stub.PutState(newPkToAddrCompositeKey, addrChangeMsg); err != nil {
		return shim.Error(err.Error())
	}

	// set new address -> key mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(newkey)); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func checkNonce(stub shim.ChaincodeStubInterface, sender, nonceStr string) error {
	key, err := stub.CreateCompositeKey(noncePrefix, []string{sender})
	if err != nil {
		return fmt.Errorf("creating composite key for %s and sender %s failed, err: %w",
			noncePrefix, sender, err)
	}

	const base = 10
	nonce, ok := new(big.Int).SetString(nonceStr, base)
	if !ok {
		return fmt.Errorf("incorrect nonce. can't read nonce %s as int", nonceStr)
	}
	data, err := stub.GetState(key)
	if err != nil {
		return err
	}
	existed := new(big.Int).SetBytes(data)
	if existed.Cmp(nonce) >= 0 {
		return fmt.Errorf("incorrect nonce. nonce from args %s less than exists %s", nonce, existed)
	}
	return stub.PutState(key, nonce.Bytes())
}

func (c *ACL) checkValidatorsSignedWithBase58Signature(message []byte, pks, signatures []string) error {
	var countValidatorsSigned int64
	if signDuplicates := checkDuplicates(signatures); len(signDuplicates) > 0 {
		return fmt.Errorf(ErrDuplicateSignatures, signDuplicates)
	}
	if pkDuplicates := checkDuplicates(pks); len(pkDuplicates) > 0 {
		return fmt.Errorf(ErrDuplicatePubKeys, pkDuplicates)
	}

	for i, encodedBase58PublicKey := range pks {
		if !IsValidator(c.init.Validators, encodedBase58PublicKey) {
			return errors.Errorf("pk %s does not belong to any validator", encodedBase58PublicKey)
		}
		countValidatorsSigned++

		// check signature
		decodedSignature := base58.Decode(signatures[i])
		decodedPublicKey, err := decodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return err
		}
		if !ed25519.Verify(decodedPublicKey, message, decodedSignature) {
			return errors.Errorf("the signature %s does not match the public key %s", signatures[i], encodedBase58PublicKey)
		}
	}

	if countValidatorsSigned < c.init.ValidatorsCount {
		return errors.Errorf("%d of %d signed", countValidatorsSigned, c.init.ValidatorsCount)
	}
	return nil
}

func (c *ACL) checkValidatorsSigned(message []byte, pks, hexSignatures []string) error {
	var countValidatorsSigned int64
	if signDublicates := checkDuplicates(hexSignatures); len(signDublicates) > 0 {
		return fmt.Errorf(ErrDuplicateSignatures, signDublicates)
	}
	if pkDublicates := checkDuplicates(pks); len(pkDublicates) > 0 {
		return fmt.Errorf(ErrDuplicatePubKeys, pkDublicates)
	}

	for i, encodedBase58PublicKey := range pks {
		if !IsValidator(c.init.Validators, encodedBase58PublicKey) {
			return errors.Errorf("pk %s does not belong to any validator", encodedBase58PublicKey)
		}
		countValidatorsSigned++

		// check signature
		decodedSignature, err := hex.DecodeString(hexSignatures[i])
		if err != nil {
			return err
		}
		decodedPublicKey, err := decodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return err
		}
		if !ed25519.Verify(decodedPublicKey, message, decodedSignature) {
			return errors.Errorf("the signature %s does not match the public key %s", base58.Encode(decodedSignature), encodedBase58PublicKey)
		}
	}

	if countValidatorsSigned < c.init.ValidatorsCount {
		return errors.Errorf("%d of %d signed", countValidatorsSigned, c.init.ValidatorsCount)
	}
	return nil
}

func getAddressByHashedKeys(stub shim.ChaincodeStubInterface, keys string) (*pb.SignedAddress, error) {
	pkToAddrCompositeKey, err := stub.CreateCompositeKey(addressPrefix, []string{keys})
	if err != nil {
		return nil, err
	}

	keyData, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return nil, err
	}
	if len(keyData) == 0 {
		return nil, fmt.Errorf("address not found by key [%s,%s]", addressPrefix, keys)
	}
	var a pb.SignedAddress
	if err = proto.Unmarshal(keyData, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func (c *ACL) checkCert(stub shim.ChaincodeStubInterface) error {
	cert, err := stub.GetCreator()
	if err != nil {
		return err
	}
	sID := &msp.SerializedIdentity{}
	if err = proto.Unmarshal(cert, sID); err != nil {
		return fmt.Errorf("could not deserialize a SerializedIdentity, err: %w", err)
	}
	b, _ := pem.Decode(sID.IdBytes)
	parsed, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	pk, ok := parsed.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("bad public key, type conversion of parsed public key failed")
	}

	hash := sha256.New()
	hash.Write(elliptic.Marshal(pk.Curve, pk.X, pk.Y))
	hashed := sha3.Sum256(cert)
	if !bytes.Equal(hashed[:], c.init.AdminSKI) &&
		!bytes.Equal(hash.Sum(nil), c.init.AdminSKI) {
		return errors.New(ErrCallerNotAdmin)
	}
	return nil
}
