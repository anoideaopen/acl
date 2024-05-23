package cc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/anoideaopen/acl/helpers"
	"golang.org/x/crypto/ed25519"
)

func verifySignature(
	publicKey []byte,
	message []byte,
	signature []byte,
) bool {
	if verifyEd25519Signature(publicKey, message, signature) {
		return true
	}

	if verifyECDSASignature(publicKey, message, signature) {
		return true
	}

	return false
}

func verifyEd25519Signature(
	publicKey []byte,
	message []byte,
	signature []byte,
) bool {
	return len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(publicKey, message, signature)
}

func verifyECDSASignature(
	publicKey []byte,
	message []byte,
	signature []byte,
) bool {
	ecdsaKey := ecdsaPublicKeyFromBytes(publicKey)
	if ecdsaKey == nil {
		return false
	}
	return ecdsa.VerifyASN1(ecdsaKey, message, signature)
}

func ecdsaPublicKeyFromBytes(bytes []byte) *ecdsa.PublicKey {
	if len(bytes) != helpers.KeyLengthECDSA {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(bytes[:helpers.KeyLengthECDSA/2]),
		Y:     new(big.Int).SetBytes(bytes[helpers.KeyLengthECDSA/2:]),
	}
}
