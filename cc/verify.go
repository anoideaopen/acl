package cc

import (
	"crypto/ed25519"
	aclproto "github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/foundation/keys/eth"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
)

func verifyValidatorSignature(
	validator *aclproto.ACLValidator,
	message []byte,
	signature []byte,
) bool {
	decodedKey := base58.Decode(validator.GetPublicKey())
	return verifySignature(decodedKey, validator.GetKeyType(), message, signature)
}

func verifySignature(
	publicKey []byte,
	keyType string,
	message []byte,
	signature []byte,
) bool {
	switch keyType {
	case pb.KeyType_secp256k1.String():
		digest := eth.Hash(message)
		return eth.Verify(publicKey, digest, signature)
	default:
		return len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(publicKey, message, signature)
	}
}
