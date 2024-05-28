package cc

import (
	"encoding/hex"
	"fmt"

	"github.com/anoideaopen/acl/helpers"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/sha3"
)

const (
	KeyTypeEd25519 KeyType = iota
	KeyTypeECDSA
	KeyTypeGOST
)

const (
	KeyTypeTextEd25519 = "ed25519"
	KeyTypeTextECDSA   = "ecdsa"
	KeyTypeTextGOST    = "gost"
)

const (
	KeyLengthEd25519 = 32
	KeyLengthECDSA   = 64
	KeyLengthGOST    = 64
)

type (
	KeyType int8

	PublicKey struct {
		InBase58          string
		Bytes             []byte
		Hash              []byte
		HashInHex         string
		HashInBase58Check string
		Type              KeyType
	}
)

var textToKeyType = map[string]KeyType{
	KeyTypeTextEd25519: KeyTypeEd25519,
	KeyTypeTextECDSA:   KeyTypeECDSA,
	KeyTypeTextGOST:    KeyTypeGOST,
}

func publicKeyFromBase58String(base58Encoded string) (PublicKey, error) {
	bytes, err := helpers.DecodeBase58PublicKey(base58Encoded)
	if err != nil {
		return PublicKey{}, fmt.Errorf("failed decoding public key: %w", err)
	}
	hashed := sha3.Sum256(bytes)

	return PublicKey{
		InBase58:          base58Encoded,
		Bytes:             bytes,
		Hash:              hashed[:],
		HashInHex:         hex.EncodeToString(hashed[:]),
		HashInBase58Check: base58.CheckEncode(hashed[1:], hashed[0]),
		Type:              KeyTypeEd25519,
	}, nil
}

func (key *PublicKey) validateLength() error {
	var expectedLength int

	switch key.Type {
	case KeyTypeECDSA:
		expectedLength = KeyLengthECDSA
	case KeyTypeGOST:
		expectedLength = KeyLengthGOST
	default:
		expectedLength = KeyLengthEd25519
	}

	if len(key.Bytes) != expectedLength {
		return fmt.Errorf("unexpected key length %d", len(key.Bytes))
	}

	return nil
}
