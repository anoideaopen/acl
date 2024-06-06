package common

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

type TestSigner struct {
	PublicKey  string
	PrivateKey string
	KeyType    string
}

func (s *TestSigner) Sign(message []byte) []byte {
	const (
		keyTypeEd25519 = "ed25519"
		keyTypeECDSA   = "ecdsa"
	)

	switch s.KeyType {
	case keyTypeEd25519:
		return ed25519.Sign([]byte(s.PrivateKey), message)

	case keyTypeECDSA:
		ecdsaKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
			},
			D: new(big.Int).SetBytes([]byte(s.PrivateKey)),
		}
		ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y = elliptic.P256().ScalarBaseMult([]byte(s.PrivateKey))

		signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, message)
		if err != nil {
			return nil
		}
		return signature

	default:
		return nil
	}
}
