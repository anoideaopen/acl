package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	eth "github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"sort"
	"strings"

	pbfound "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/sha3"
)

type UserFoundationMultisigned struct {
	Users              []*client.UserFoundation
	AddressBase58Check string
	UserID             string
}

// NewUserFoundationMultisigned creates multisigned user based on specified key type and policy
func NewUserFoundationMultisigned(keyType string, n int) *UserFoundationMultisigned {
	var pKeys [][]byte
	userMultisigned := &UserFoundationMultisigned{
		Users:  make([]*client.UserFoundation, 0),
		UserID: "testUserMultisigned",
	}
	for i := 0; i < n; i++ {
		user := client.NewUserFoundation(keyType)
		userMultisigned.Users = append(userMultisigned.Users, user)
		pKeys = append(pKeys, user.PublicKeyBytes)
	}

	binPubKeys := make([][]byte, len(pKeys))
	for i, k := range pKeys {
		binPubKeys[i] = k
	}
	sort.Slice(binPubKeys, func(i, j int) bool {
		return bytes.Compare(binPubKeys[i], binPubKeys[j]) < 0
	})

	hashedAddr := sha3.Sum256(bytes.Join(binPubKeys, []byte("")))
	userMultisigned.AddressBase58Check = base58.CheckEncode(hashedAddr[1:], hashedAddr[0])
	return userMultisigned
}

// Sign adds sign for multisigned user
func (u *UserFoundationMultisigned) Sign(args ...string) (publicKeysBase58 []string, signMsgs [][]byte, err error) {
	msg := make([]string, 0, len(args)+len(u.Users))
	msg = append(msg, args...)
	for _, user := range u.Users {
		msg = append(msg, user.PublicKeyBase58)
		publicKeysBase58 = append(publicKeysBase58, user.PublicKeyBase58)
	}

	bytesToSign := sha3.Sum256([]byte(strings.Join(msg, "")))

	for _, user := range u.Users {
		var signMsg []byte
		switch user.PublicKeyType {
		case pbfound.KeyType_ed25519.String():
			signMsg = signMessageEd25519(user.PrivateKeyBytes, bytesToSign[:])
			err = verifyEd25519(user.PublicKeyBytes, bytesToSign[:], signMsg)
			if err != nil {
				return nil, nil, err
			}

		case pbfound.KeyType_secp256k1.String():
			signMsg = signMessageSecp256k1(user.PrivateKeyBytes, bytesToSign[:])
			err = verifySecp256k1(user.PublicKeyBytes, bytesToSign[:], signMsg)
			if err != nil {
				return nil, nil, err
			}

		default:
			return nil, nil, errors.New("unknown key type")
		}

		signMsgs = append(signMsgs, signMsg)
	}

	return
}

// PublicKey - returns public key for multisigned user based on keys of its users
func (u *UserFoundationMultisigned) PublicKey() string {
	var multisignedKeys string
	for _, user := range u.Users {
		multisignedKeys = multisignedKeys + user.PublicKeyBase58 + MultisignKeyDelimeter
	}

	return strings.TrimRight(multisignedKeys, MultisignKeyDelimeter)
}

// signMessageEd25519 - sign arguments with private key in ed25519
func signMessageEd25519(privateKey ed25519.PrivateKey, msgToSign []byte) []byte {
	sig := ed25519.Sign(privateKey, msgToSign)
	return sig
}

// signMessageSecp256k1 - signs a message with private key in secp256k1
func signMessageSecp256k1(privateKeyBytes []byte, msgToSign []byte) []byte {
	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = eth.S256()
	privateKey.D = new(big.Int).SetBytes(privateKeyBytes)

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, msgToSign)
	if err != nil {
		return nil
	}
	return sig
}

// verifyEd25519 - verify publicKey with message and signed message
func verifyEd25519(publicKey ed25519.PublicKey, bytesToSign []byte, sMsg []byte) error {
	if !ed25519.Verify(publicKey, bytesToSign, sMsg) {
		return errors.New("valid signature rejected")
	}
	return nil
}

// verifySecp256k1 - verify publicKey in secp256k1 with message and signed message
func verifySecp256k1(publicKeyBytes []byte, message []byte, sig []byte) error {
	const lenSecp256k1Key = 64

	if publicKeyBytes[0] == 0x04 {
		publicKeyBytes = publicKeyBytes[1:]
	}

	if len(publicKeyBytes) != lenSecp256k1Key {
		return errors.New("invalid length of secp256k1 key")
	}

	publicKey := &ecdsa.PublicKey{
		Curve: eth.S256(),
		X:     new(big.Int).SetBytes(publicKeyBytes[:lenSecp256k1Key/2]),
		Y:     new(big.Int).SetBytes(publicKeyBytes[lenSecp256k1Key/2:]),
	}

	if !ecdsa.VerifyASN1(publicKey, message, sig) {
		return errors.New("secp256k1 signature rejected")
	}

	return nil
}
