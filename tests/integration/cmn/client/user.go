package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/sha3"
)

type UserFoundation struct {
	PrivateKey         ed25519.PrivateKey
	PublicKey          ed25519.PublicKey
	PublicKeyBase58    string
	AddressBase58Check string
	UserID             string
}

type UserFoundationMultisigned struct {
	Users              []*UserFoundation
	AddressBase58Check string
	UserID             string
}

func NewUserFoundation() *UserFoundation {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return &UserFoundation{}
	}
	publicKeyBase58 := base58.Encode(publicKey)
	hash := sha3.Sum256(publicKey)
	addressBase58Check := base58.CheckEncode(hash[1:], hash[0])

	return &UserFoundation{
		PrivateKey:         privateKey,
		PublicKey:          publicKey,
		PublicKeyBase58:    publicKeyBase58,
		AddressBase58Check: addressBase58Check,
		UserID:             "testuser",
	}
}

func NewUserFoundationMultisigned(n int) *UserFoundationMultisigned {
	var pKeys []ed25519.PublicKey
	userMultisigned := &UserFoundationMultisigned{
		Users:  make([]*UserFoundation, 0),
		UserID: "testUserMultisigned",
	}
	for i := 0; i < n; i++ {
		user := NewUserFoundation()
		userMultisigned.Users = append(userMultisigned.Users, user)
		pKeys = append(pKeys, user.PublicKey)
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

func UserFoundationFromPrivateKey(privateKey ed25519.PrivateKey) (*UserFoundation, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("type requireion failed")
	}

	publicKeyBase58 := base58.Encode(publicKey)
	hash := sha3.Sum256(publicKey)
	addressBase58Check := base58.CheckEncode(hash[1:], hash[0])

	return &UserFoundation{
		PrivateKey:         privateKey,
		PublicKey:          publicKey,
		PublicKeyBase58:    publicKeyBase58,
		AddressBase58Check: addressBase58Check,
		UserID:             "testuser",
	}, nil
}

func UserFoundationFromBase58CheckPrivateKey(base58Check string) (*UserFoundation, error) {
	decode, ver, err := base58.CheckDecode(base58Check)
	if err != nil {
		return nil, fmt.Errorf("check decode: %w", err)
	}
	privateKey := ed25519.PrivateKey(append([]byte{ver}, decode...))

	return UserFoundationFromPrivateKey(privateKey)
}

func (u *UserFoundation) Sign(args ...string) (publicKeyBase58 string, signMsg []byte, err error) {
	publicKeyBase58 = u.PublicKeyBase58
	msg := make([]string, 0, len(args)+1)
	msg = append(msg, args...)
	msg = append(msg, publicKeyBase58)

	bytesToSign := sha3.Sum256([]byte(strings.Join(msg, "")))

	signMsg = signMessage(u.PrivateKey, bytesToSign[:])
	err = verifyEd25519(u.PublicKey, bytesToSign[:], signMsg)
	if err != nil {
		return "", nil, err
	}

	return
}

func (u *UserFoundation) SetUserID(id string) {
	if len(id) != 0 {
		u.UserID = id
	}
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
		sMsg := signMessage(user.PrivateKey, bytesToSign[:])
		err = verifyEd25519(user.PublicKey, bytesToSign[:], sMsg)
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
		err := errors.New("valid signature rejected")
		return err
	}
	return nil
}
