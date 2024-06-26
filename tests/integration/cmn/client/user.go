package client

import (
	"bytes"
	"crypto/ed25519"
	"errors"
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

func NewUserFoundationMultisigned(n int) *UserFoundationMultisigned {
	var pKeys []ed25519.PublicKey
	userMultisigned := &UserFoundationMultisigned{
		Users:  make([]*client.UserFoundation, 0),
		UserID: "testUserMultisigned",
	}
	for i := 0; i < n; i++ {
		user := client.NewUserFoundation(pbfound.KeyType_ed25519.String())
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
		sMsg := signMessage(user.PrivateKeyBytes, bytesToSign[:])
		err = verifyEd25519(user.PublicKeyBytes, bytesToSign[:], sMsg)
		if err != nil {
			return nil, nil, err
		}
		signMsgs = append(signMsgs, sMsg)
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

// signMessage - sign arguments with private key in ed25519
func signMessage(privateKey ed25519.PrivateKey, msgToSign []byte) []byte {
	sig := ed25519.Sign(privateKey, msgToSign)
	return sig
}

// verifyEd25519 - verify publicKey with message and signed message
func verifyEd25519(publicKey ed25519.PublicKey, bytesToSign []byte, sMsg []byte) error {
	if !ed25519.Verify(publicKey, bytesToSign, sMsg) {
		return errors.New("valid signature rejected")
	}
	return nil
}
