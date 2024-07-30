package unit

import (
	"encoding/hex"
	"testing"

	"github.com/anoideaopen/acl/tests/common"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
)

func TestAddUserSecp256k1PublicKey(t *testing.T) {
	t.Parallel()

	const (
		testKeyECDSA = "041d16de99a91959437215b163172a0402346557eabdcb71535c287cba153cea65241a13a33ed672abc3223305b7e240cc8782469612c6b1f59ba0007b0248ce52"
		testAddress  = "9xVBTc5LmtxJN5AEAacJu9wiLwcuLeW6uj2afzWKHQczc1dWG"
	)

	bytes, err := hex.DecodeString(testKeyECDSA)
	require.NoError(t, err)
	userPublicKey := base58.Encode(bytes)

	stub := common.StubCreateAndInit(t)

	t.Run("[negative] add user with wrong key type", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     userPublicKey,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeEd25519,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "unexpected key length",
		}

		resp := addUser(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})

	t.Run("[negative] add user with wrong key length", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     userPublicKey[:len(userPublicKey)-2],
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeSecp256k1,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "incorrect len of decoded from base58 public key",
		}

		resp := addUser(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})

	t.Run("add user with secp256k1 key", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     userPublicKey,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeSecp256k1,
			respStatus:     int32(shim.OK),
			errorMsg:       "",
		}

		resp := addUserWithPublicKeyType(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})

	t.Run("[negative] add user with secp256k1 key again", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     userPublicKey,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeSecp256k1,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "already exists",
		}

		resp := addUserWithPublicKeyType(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})
}

func TestAddUserGostPublicKey(t *testing.T) {
	t.Parallel()

	const (
		testKeyGost = "b5d49053fdb30abf8f0a5d668639fef83d8ed21cb5e1f0a8ba7e8350a11ab02270955c29d0f384879bcd2d775867dd59b7514868fa48a86ed4652d2af58341cf"
		testAddress = "WkSoEbdqsUbkAgsACNpeufp9HUstrtqpRSya4gebsuNn1S17D"
	)

	bytes, err := hex.DecodeString(testKeyGost)
	require.NoError(t, err)
	userPublicKey := base58.Encode(bytes)

	stub := common.StubCreateAndInit(t)

	t.Run("[negative] add user with gost public key with wrong length", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     userPublicKey[:len(userPublicKey)-2],
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeGost,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "incorrect len of decoded from base58 public key",
		}

		resp := addUserWithPublicKeyType(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})

	t.Run("add user with gost public key", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     userPublicKey,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeGost,
			respStatus:     int32(shim.OK),
			errorMsg:       "",
		}

		resp := addUserWithPublicKeyType(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})
}
