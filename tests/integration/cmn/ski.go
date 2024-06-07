package cmn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func ReadSKI(pathToPrivateKey string) (string, error) {
	privateKeyFile, err := os.ReadFile(pathToPrivateKey)
	if err != nil {
		return "", fmt.Errorf("read private key file: %w", err)
	}
	privateKey, err := pemToPrivateKey(privateKeyFile, []byte{})
	if err != nil {
		return "", fmt.Errorf("parse private key file content: %w", err)
	}

	ski := sKI(privateKey)
	return hex.EncodeToString(ski), nil
}

// sKI returns the subject key identifier of this key.
func sKI(privKey *ecdsa.PrivateKey) []byte {
	if privKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func pemToPrivateKey(raw []byte, pwd []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
	}

	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: %w", err)
		}

		key, err := derToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	key, err := derToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

func derToPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if keyi, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch v := keyi.(type) {
		case *ecdsa.PrivateKey:
			return v, nil
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}

	return nil, errors.New("invalid key type. The DER must contain an ecdsa.PrivateKey")
}
