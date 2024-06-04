package cc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"

	"github.com/anoideaopen/acl/helpers"
	aclproto "github.com/anoideaopen/acl/proto"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
)

func verifyValidatorSignature(
	validator *aclproto.ACLValidator,
	message []byte,
	signature []byte,
) bool {
	decodedKey := base58.Decode(validator.GetPublicKey())
	switch validator.GetKeyType() {
	case pb.KeyType_ecdsa.String():
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
