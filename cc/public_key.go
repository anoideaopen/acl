package cc

import (
	"encoding/hex"
	"fmt"

	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/sha3"
)

const (
	KeyLengthEd25519 = 32
	KeyLengthECDSA   = 64
	KeyLengthGOST    = 64
)

type PublicKey struct {
	InBase58          string
	Bytes             []byte
	Hash              []byte
	HashInHex         string
	HashInBase58Check string
	Type              string
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
		Type:              helpers.DefaultPublicKeyType(),
	}, nil
}

func (key *PublicKey) validateLength() error {
	var expectedLength int

	switch key.Type {
	case pb.KeyType_ecdsa.String():
		expectedLength = KeyLengthECDSA
	case pb.KeyType_gost.String():
		expectedLength = KeyLengthGOST
	default:
		expectedLength = KeyLengthEd25519
	}

	if len(key.Bytes) != expectedLength {
		return fmt.Errorf("unexpected key length %d", len(key.Bytes))
	}

	return nil
}

func (key *PublicKey) verifySignature(
	message []byte,
	signature []byte,
) bool {
	switch key.Type {
	case pb.KeyType_ecdsa.String():
		return verifyECDSASignature(key.Bytes, message, signature)
	default:
		return verifyEd25519Signature(key.Bytes, message, signature)
	}
}
