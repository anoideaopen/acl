package common

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"math/big"

	eth "github.com/ethereum/go-ethereum/crypto"
)

const (
	KeyTypeEd25519   = "ed25519"
	KeyTypeSecp256k1 = "secp256k1"
	KeyTypeGost      = "gost"
)

type TestSigner struct {
	PublicKey  string
	PrivateKey string
	KeyType    string
}

func (s *TestSigner) Sign(message []byte) []byte {
	switch s.KeyType {
	case KeyTypeEd25519:
		return ed25519.Sign([]byte(s.PrivateKey), message)

	case KeyTypeSecp256k1:
		secp256k1Key := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: eth.S256(),
			},
			D: new(big.Int).SetBytes([]byte(s.PrivateKey)),
		}

		signature, err := ecdsa.SignASN1(rand.Reader, secp256k1Key, message)
		if err != nil {
			return nil
		}
		return signature

	default:
		return nil
	}
}
