package cc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"math/big"

	"github.com/anoideaopen/acl/helpers"
	aclproto "github.com/anoideaopen/acl/proto"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	eth "github.com/ethereum/go-ethereum/crypto"
)

func verifyValidatorSignature(
	validator *aclproto.ACLValidator,
	message []byte,
	signature []byte,
) bool {
	keyType := validator.GetPublicKey()
	decodedKey := base58.Decode(keyType)
	switch keyType {
	case pb.KeyType_ed25519.String():
		return verifyEd25519Signature(decodedKey, message, signature)
	case pb.KeyType_secp256k1.String():
		return verifySecp256k1Signature(decodedKey, message, signature)
	default:
		return false
	}
}

func verifyEd25519Signature(
	publicKey []byte,
	message []byte,
	signature []byte,
) bool {
	return len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(publicKey, message, signature)
}

func verifySecp256k1Signature(
	publicKeyBytes []byte,
	message []byte,
	signature []byte,
) bool {
	publicKey := secp256k1PublicKeyFromBytes(publicKeyBytes)
	if publicKey == nil {
		return false
	}
	return ecdsa.VerifyASN1(publicKey, message, signature)
}

func secp256k1PublicKeyFromBytes(bytes []byte) *ecdsa.PublicKey {
	if len(bytes) == helpers.KeyLengthSecp256k1+1 && bytes[0] == helpers.PrefixUncompressedSecp259k1Key {
		bytes = bytes[1:]
	}
	if len(bytes) != helpers.KeyLengthSecp256k1 {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: eth.S256(),
		X:     new(big.Int).SetBytes(bytes[:helpers.KeyLengthSecp256k1/2]),
		Y:     new(big.Int).SetBytes(bytes[helpers.KeyLengthSecp256k1/2:]),
	}
}
