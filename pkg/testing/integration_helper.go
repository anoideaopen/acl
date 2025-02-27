package testing

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/anoideaopen/acl/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

type ACLAdminKey struct {
	PublicBase58 string
	Type         string
}

func GenerateConfig(peerBackendUserPriateKey *ecdsa.PrivateKey, keyList ...ACLAdminKey) ([]byte, error) {
	var err error
	var rawConfig []byte

	skiBackend, err := ski(peerBackendUserPriateKey)
	if err != nil {
		return nil, fmt.Errorf("get ski backend: %w", err)
	}
	skiBackendHex := hex.EncodeToString(skiBackend)

	aclAdmins := []*proto.ACLValidator{}
	for _, key := range keyList {
		aclAdmins = append(aclAdmins, &proto.ACLValidator{
			PublicKey: key.PublicBase58,
			KeyType:   key.Type,
		})
	}
	aclCfg := &proto.ACLConfig{
		AdminSKIEncoded: skiBackendHex,
		Validators:      aclAdmins,
	}

	rawConfig, err = protojson.Marshal(aclCfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return rawConfig, nil
}

// ski returns the subject key identifier of this key.
func ski(privKey *ecdsa.PrivateKey) ([]byte, error) {
	if privKey == nil {
		return nil, nil
	}

	// Marshall the public key
	edchKey, err := privKey.ECDH()
	if err != nil {
		return nil, err
	}

	raw := edchKey.PublicKey().Bytes()

	// Hash it
	hash := sha256.Sum256(raw)
	return hash[:], nil
}
