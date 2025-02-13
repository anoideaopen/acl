package cc

import (
	"crypto/ed25519"
	"crypto/sha3"
	"fmt"

	aclproto "github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/foundation/keys/eth"
	"github.com/anoideaopen/foundation/keys/gost"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
)

func verifyValidatorSignature(
	validator *aclproto.ACLValidator,
	message []byte,
	signature []byte,
) (bool, error) {
	decodedKey := base58.Decode(validator.GetPublicKey())
	return verifySignature(decodedKey, validator.GetKeyType(), message, signature)
}

func verifySignature(
	publicKey []byte,
	keyType string,
	message []byte,
	signature []byte,
) (bool, error) {
	switch keyType {
	case pb.KeyType_ed25519.String():
		messageDigest := sha3.Sum256(message)
		return len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(publicKey, messageDigest[:], signature), nil
	case pb.KeyType_secp256k1.String():
		messageDigest := sha3.Sum256(message)
		hash := eth.Hash(messageDigest[:])
		return eth.Verify(publicKey, hash, signature), nil
	case pb.KeyType_gost.String():
		digest := gost.Sum256(message)
		return gost.Verify(publicKey, digest[:], signature)
	default:
		return false, fmt.Errorf("unknown public key type: %s", keyType)
	}
}
