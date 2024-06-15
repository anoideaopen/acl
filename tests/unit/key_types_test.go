package unit

import (
	"encoding/hex"
	"testing"

	"github.com/anoideaopen/acl/tests/common"
	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
)

func TestAddUserSecp256k1PublicKey(t *testing.T) {
	t.Parallel()

	const (
		testKeyECDSA = "7cbbb6989aa2df8926ebd925fa87eb843f3328b4b2ba2f35532309c759af96c9a8b0a824f2f65c5515181638546dd13917d4be3e6bf7370934dc845443788381"
		testAddress  = "2gNhUTgbNJEqnwFfrWLpdtQeGj2hxVz7d3VgzNJBHjpPpDhMVo"
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

	t.Run("[negative] add user with ecdsa key again", func(t *testing.T) {
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

func TestAddUserSecp256k1WithPrefixPublicKey(t *testing.T) {
	t.Parallel()

	const (
		testKeyECDSA = "04dcbf4f2914fdb419fc92cd86383c137fec5dfa3c9f1befed67da16f3bcd9ea09ceb43f49e77549496ca2ca60bba3bb09f8dac72a6fd12ac3b8bac8b51f2c5ee3"
		testAddress  = "HfqBDFi6uQFGENqLVLfmR1LKmo8Ghzpd9NhjMZbVqmLknyBTg"
	)

	bytes, err := hex.DecodeString(testKeyECDSA)
	require.NoError(t, err)
	userPublicKey := base58.Encode(bytes)

	stub := common.StubCreateAndInit(t)

	t.Run("add user with secp256k1 key with 0x04 prefix", func(t *testing.T) {
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
