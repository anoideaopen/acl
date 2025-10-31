package cc

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"

	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
)

type PublicKey struct {
	InBase58          string
	Bytes             []byte
	Hash              []byte
	HashInHex         string
	HashInBase58Check string
	Type              string
}

func PublicKeyFromBase58String(base58Encoded string) (PublicKey, error) {
	bytes, err := helpers.DecodeBase58PublicKey(base58Encoded)
	if err != nil {
		return PublicKey{}, fmt.Errorf("failed decoding public key: %w", err)
	}
	hashed := sha3.Sum256(bytes)

	key := PublicKey{
		InBase58:          base58Encoded,
		Bytes:             bytes,
		Hash:              hashed[:],
		HashInHex:         hex.EncodeToString(hashed[:]),
		HashInBase58Check: base58.CheckEncode(hashed[1:], hashed[0]),
		Type:              helpers.DefaultPublicKeyType(),
	}

	key.setTypeByKeyLength()

	return key, nil
}

func (key *PublicKey) setTypeByKeyLength() {
	if key.isEd25519() {
		key.Type = pb.KeyType_ed25519.String()
		return
	}
	if key.isSecp256k1() {
		key.Type = pb.KeyType_secp256k1.String()
		return
	}
	if key.isGost() {
		key.Type = pb.KeyType_gost.String()
		return
	}
	key.Type = helpers.DefaultPublicKeyType()
}

func (key *PublicKey) isSecp256k1() bool {
	return len(key.Bytes) == helpers.KeyLengthSecp256k1 && key.Bytes[0] == helpers.PrefixUncompressedSecp259k1Key
}

func (key *PublicKey) isEd25519() bool {
	return len(key.Bytes) == helpers.KeyLengthEd25519
}

func (key *PublicKey) isGost() bool {
	return len(key.Bytes) == helpers.KeyLengthGOST
}

func (key *PublicKey) validateLength() error {
	valid := false

	switch key.Type {
	case pb.KeyType_secp256k1.String():
		valid = key.isSecp256k1()
	case pb.KeyType_gost.String():
		valid = key.isGost()
	default:
		valid = key.isEd25519()
	}

	if !valid {
		return fmt.Errorf("unexpected key length %d", len(key.Bytes))
	}

	return nil
}

func (key *PublicKey) verifySignature(
	digest []byte,
	signature []byte,
) (bool, error) {
	return verifySignature(key.Bytes, key.Type, digest, signature)
}
