package cc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/anoideaopen/acl/helpers"
	aclproto "github.com/anoideaopen/acl/proto"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ed25519"
)

func verifySignatureWithPublicKey(
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

func verifySignatureWithPublicKeyWithType(
	publicKey []byte,
	keyType KeyType,
	message []byte,
	signature []byte,
) bool {
	switch keyType {
	case KeyTypeECDSA:
		return verifyECDSASignature(publicKey, message, signature)
	default:
		return verifyEd25519Signature(publicKey, message, signature)
	}
}

func verifySignatureWithValidator(
	validator *aclproto.ACLValidator,
	message []byte,
	signature []byte,
) bool {
	decodedKey := base58.Decode(validator.PublicKey)
	switch validator.KeyType {
	case KeyTypeTextECDSA:
		return verifyECDSASignature(decodedKey, message, signature)
	default:
		return verifyEd25519Signature(decodedKey, message, signature)
	}
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
