package cc

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/anoideaopen/acl/cc/errs"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

type CheckKeysRequest struct {
	PublicKeys []PublicKey
}

func checkKeysRequestFromArguments(args []string) (CheckKeysRequest, error) {
	const (
		indexKeys          = 0
		requiredArgsCount  = indexKeys + 1
		multiSignSeparator = "/"
	)

	var err error

	if len(args) < requiredArgsCount {
		return CheckKeysRequest{},
			fmt.Errorf("incorrect number of arguments: %d, but this method expects: N pubkeys", len(args))
	}

	keysInArgs := args[indexKeys]
	if len(keysInArgs) == 0 {
		return CheckKeysRequest{},
			errors.New(errs.ErrEmptyPubKey)
	}

	keysInBase58 := strings.Split(keysInArgs, multiSignSeparator)

	publicKeys := make([]PublicKey, len(keysInBase58))
	for i, key := range keysInBase58 {
		publicKeys[i], err = publicKeyFromBase58String(key)
		if err != nil {
			return CheckKeysRequest{}, fmt.Errorf("%w, input: '%s'", err, keysInArgs)
		}
	}

	return CheckKeysRequest{PublicKeys: publicKeys}, nil
}

func checkKeys(stub shim.ChaincodeStubInterface, request CheckKeysRequest) (pb.AclResponse, error) {
	const keysSeparator = ""

	uniqPks := make(map[string]struct{})
	keysBytesSorted := make([][]byte, len(request.PublicKeys))

	for i, publicKey := range request.PublicKeys {
		if _, ok := uniqPks[publicKey.InBase58]; ok {
			return pb.AclResponse{}, errors.New("duplicated public keys")
		}
		uniqPks[publicKey.InBase58] = struct{}{}
		keysBytesSorted[i] = publicKey.Bytes
	}

	sort.Slice(
		keysBytesSorted,
		func(i, j int) bool {
			return bytes.Compare(keysBytesSorted[i], keysBytesSorted[j]) < 0
		},
	)
	hashed := sha3.Sum256(bytes.Join(keysBytesSorted, []byte(keysSeparator)))
	hashedKeysInHex := hex.EncodeToString(hashed[:])

	var (
		err           error
		signedAddress *pb.SignedAddress
		accountInfo   *pb.AccountInfo
		keyTypes      = make([]pb.KeyType, len(request.PublicKeys))
	)

	if signedAddress, err = getAddressByHashedKeys(stub, hashedKeysInHex); err != nil {
		return pb.AclResponse{}, fmt.Errorf("failed reading signed address from state: %w", err)
	}

	foundBlocked := false
	for i, publicKey := range request.PublicKeys {
		if publicKey.Type, err = readPublicKeyType(stub, publicKey.HashInHex); err != nil {
			return pb.AclResponse{}, fmt.Errorf("failed reading key type from state: %w", err)
		}

		keyTypes[i] = pb.KeyType(pb.KeyType_value[publicKey.Type])

		if !foundBlocked {
			var address *pb.SignedAddress

			if address, err = getAddressByHashedKeys(stub, publicKey.HashInHex); err != nil {
				return pb.AclResponse{}, fmt.Errorf("failed reading signed address from state: %w", err)
			}

			if accountInfo, err = getAccountInfo(stub, address.GetAddress().AddrString()); err != nil {
				return pb.AclResponse{}, fmt.Errorf("failed reading account info from state: %w", err)
			}

			foundBlocked = isAccountInfoInBlockedLists(accountInfo)
		}
	}

	return pb.AclResponse{
			Address:  signedAddress,
			Account:  accountInfo,
			KeyTypes: keyTypes,
		},
		nil
}
