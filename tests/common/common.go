package common

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/proto"
	"github.com/btcsuite/btcutil/base58"
	eth "github.com/ethereum/go-ethereum/crypto"
	pb "github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/encoding/protojson"
)

// ACL API Functions
const (
	FnAddUser                        = "addUser"
	FnAddUserWithPublicKeyType       = "addUserWithPublicKeyType"
	FnGetUser                        = "getUser"
	FnAddMultisig                    = "addMultisig"
	FnAddMultisigWithBase58Signature = "addMultisigWithBase58Signature"
	FnAddToList                      = "addToList"
	FnDelFromList                    = "delFromList"
	FnCheckKeys                      = "checkKeys"
	FnGetAccInfoFn                   = "getAccountInfo"
	FnChangePublicKey                = "changePublicKey"
	FnChangeMultisigPublicKey        = "changeMultisigPublicKey"
	FnSetKYC                         = "setkyc"
	FnAddAdditionalKey               = "addAdditionalKey"
	FnRemoveAdditionalKey            = "removeAdditionalKey"
)

// Access Matrix ACL API Functions
const (
	FnAddRights       = "addRights"
	FnRemoveRights    = "removeRights"
	FnGetAccOpRight   = "getAccountOperationRight"
	FnGetAccAllRights = "getAccountAllRights"
	FnGetOpAllRights  = "getOperationAllRights"
)

const (
	PubKey           = "aGGiDES6PZsZYz2ncsEXz8mXPxZRhVzMbgJFNAA7EA8"
	TestAddr         = "2datxk5TmB1spSNn9enVo11dcpgmUoSBSqCx5cCGoWq8qTbZog"
	TestWrongAddress = "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt"
	TestCreatorMSP   = "platformMSP"
)

const (
	DefaultReason = "because..."
)

var (
	TestUsers = []TestSigner{
		{
			PublicKey:  "A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4",
			PrivateKey: "3aDebSkgXq37VPrzThboaV8oMMbYXrRAt7hnGrod4PNMnGfXjh14TY7cQs8eVT46C4RK4ZyNKLrBmyD5CYZiFmkr",
			KeyType:    KeyTypeEd25519,
		},
		{
			PublicKey:  "5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5",
			PrivateKey: "5D2BpuHZwik9zPFuaqba4zbvNP8TB7PQ6usZke5bufPbKf8xG6ZMHReBqwKw9aDfpTaNfaRsg1j2zVZWrX8hg18D",
			KeyType:    KeyTypeEd25519,
		},
		{
			PublicKey:  "6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4",
			PrivateKey: "3sK2wHWxU58kzAeFtShDMsPm5Qh74NAWgfwCmdKyzvp4npivEDDEp14WgQpg7KGaVNF7qWyyMvkKPzGddVkxagNN",
			KeyType:    KeyTypeEd25519,
		},
	}

	TestUsersDifferentKeyTypes = []TestSigner{
		{
			PublicKey:  "A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4",
			PrivateKey: "3aDebSkgXq37VPrzThboaV8oMMbYXrRAt7hnGrod4PNMnGfXjh14TY7cQs8eVT46C4RK4ZyNKLrBmyD5CYZiFmkr",
			KeyType:    KeyTypeEd25519,
		},
		{
			// secp256k1 key with 0x04 prefix
			PublicKey:  "RtR8wrDuNvVXHNraBkNyeR6YVCdfUL6dWGXk1GAz2wPkp41BUYApzjVcJ9DutTmTZCSPQdKf3UgiuWrGCuL4C7fg",
			PrivateKey: "CPjbqe7PzmgimpTdvvAuHsF8KcCw8ac3Sj8phUp2duuS",
			KeyType:    KeyTypeSecp256k1,
		},
		{
			// secp256k1 key without 0x04 prefix
			PublicKey:  "4DorLT9cRqaUeiDsBtDmm2Gwz18CqGsLn3f4eNLPi8LfzaS3h29aGZXp8aSFMEb8K3BEDA3Z9kFnTqD2TuAud15V",
			PrivateKey: "8XfQpgs3iBeJ1tSKzsdCU9t7Jd8vbxcLsrDgGHq78C4x",
			KeyType:    KeyTypeSecp256k1,
		},
	}

	TestAdminSKI = []byte("dc752d6afb51c33327b7873fdb08adb91de15ee7c88f4f9949445aeeb8ea4e99")

	TestValidatorsPublicKeysArgs = [][]byte{
		[]byte("A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4"),
		[]byte("5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5"),
		[]byte("6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4"),
	}

	TestInitArgs = append(
		[][]byte{
			TestAdminSKI,
			[]byte(strconv.Itoa(len(TestValidatorsPublicKeysArgs))),
		},
		TestValidatorsPublicKeysArgs...,
	)

	TestValidatorsPrivateKeysArgs = [][]byte{
		[]byte("3aDebSkgXq37VPrzThboaV8oMMbYXrRAt7hnGrod4PNMnGfXjh14TY7cQs8eVT46C4RK4ZyNKLrBmyD5CYZiFmkr"),
		[]byte("5D2BpuHZwik9zPFuaqba4zbvNP8TB7PQ6usZke5bufPbKf8xG6ZMHReBqwKw9aDfpTaNfaRsg1j2zVZWrX8hg18D"),
		[]byte("3sK2wHWxU58kzAeFtShDMsPm5Qh74NAWgfwCmdKyzvp4npivEDDEp14WgQpg7KGaVNF7qWyyMvkKPzGddVkxagNN"),
	}

	TestInitConfig = &proto.ACLConfig{
		AdminSKIEncoded: string(TestAdminSKI),
		Validators: []*proto.ACLValidator{
			{
				PublicKey: TestUsersDifferentKeyTypes[0].PublicKey,
				KeyType:   TestUsersDifferentKeyTypes[0].KeyType,
			},
			{
				PublicKey: TestUsersDifferentKeyTypes[1].PublicKey,
				KeyType:   TestUsersDifferentKeyTypes[1].KeyType,
			},
			{
				PublicKey: TestUsersDifferentKeyTypes[2].PublicKey,
				KeyType:   TestUsersDifferentKeyTypes[2].KeyType,
			},
		},
	}

	AdminCertPath = "admin_cert.pem"
	UserCertPath  = "user_cert.pem"

	AdminCert = "-----BEGIN CERTIFICATE-----\nMIICSDCCAe6gAwIBAgIQAJwYy5PJAYSC1i0UgVN5bjAKBggqhkjOPQQDAjCBhzEL\nMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG\ncmFuY2lzY28xIzAhBgNVBAoTGmF0b215emUudWF0LmRsdC5hdG9teXplLmNoMSYw\nJAYDVQQDEx1jYS5hdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDAeFw0yMDEwMTMw\nODU2MDBaFw0zMDEwMTEwODU2MDBaMHUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD\nYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ4wDAYDVQQLEwVhZG1p\nbjEpMCcGA1UEAwwgQWRtaW5AYXRvbXl6ZS51YXQuZGx0LmF0b215emUuY2gwWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGQX9IhgjCtd3mYZ9DUszmUgvubepVMPD5\nFlwjCglB2SiWuE2rT/T5tHJsU/Y9ZXFtOOpy/g9tQ/0wxDWwpkbro00wSzAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADArBgNVHSMEJDAigCBSv0ueZaB3qWu/\nAwOtbOjaLd68woAqAklfKKhfu10K+DAKBggqhkjOPQQDAgNIADBFAiEAoKRQLe4U\nFfAAwQs3RCWpevOPq+J8T4KEsYvswKjzfJYCIAs2kOmN/AsVUF63unXJY0k9ktfD\nfAaqNRaboY1Yg1iQ\n-----END CERTIFICATE-----"
	UserCert  = "-----BEGIN CERTIFICATE-----\nMIICSDCCAe+gAwIBAgIQAO3rcbDmH/0f1DWQgKhYZTAKBggqhkjOPQQDAjCBhzEL\nMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG\ncmFuY2lzY28xIzAhBgNVBAoTGmF0b215emUudWF0LmRsdC5hdG9teXplLmNoMSYw\nJAYDVQQDEx1jYS5hdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDAeFw0yMDEwMTMw\nODU2MDBaFw0zMDEwMTEwODU2MDBaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD\nYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQLEwZjbGll\nbnQxKTAnBgNVBAMMIFVzZXIyQGF0b215emUudWF0LmRsdC5hdG9teXplLmNoMFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEch+6dRC3SDIZhCSYNNAYE2T7eONz3m/i\n0oEM+/7VbHUJE+IkwZBmV8aCxC177t4OIcOBZuO4fLijnbgipf1cW6NNMEswDgYD\nVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwKwYDVR0jBCQwIoAgUr9LnmWgd6lr\nvwMDrWzo2i3evMKAKgJJXyioX7tdCvgwCgYIKoZIzj0EAwIDRwAwRAIgV71buT7/\n2j+dznSFP1es5KJd1c5IANDzjR9cP5qd/kICIGTjJO5rcOv322nPWaTWr5XUtR3R\n/K0Elk9CQQBTzfqY\n-----END CERTIFICATE-----"

	// MockUsersKeys stores pubkey -> secret key mapping
	MockUsersKeys = map[string]string{
		TestUsers[0].PublicKey: TestUsers[0].PrivateKey,
		TestUsers[1].PublicKey: TestUsers[1].PrivateKey,
		TestUsers[2].PublicKey: TestUsers[2].PrivateKey,
	}

	MockValidatorsKeys = map[string]string{
		TestUsersDifferentKeyTypes[0].PublicKey: TestUsersDifferentKeyTypes[0].PrivateKey,
		TestUsersDifferentKeyTypes[1].PublicKey: TestUsersDifferentKeyTypes[1].PrivateKey,
		TestUsersDifferentKeyTypes[2].PublicKey: TestUsersDifferentKeyTypes[2].PrivateKey,
	}

	DuplicateMockUsersSecretKeys = []string{
		TestUsers[0].PrivateKey,
		TestUsers[1].PrivateKey,
		TestUsers[1].PrivateKey,
		TestUsers[1].PrivateKey,
	}
)

// MarshalIdentity marshals creator identities
func MarshalIdentity(creatorMSP string, creatorCert []byte) ([]byte, error) {
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: creatorCert}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if pemBytes == nil {
		return nil, errors.New("encoding of identity failed")
	}

	creator := &msp.SerializedIdentity{Mspid: creatorMSP, IdBytes: pemBytes}
	marshaledIdentity, err := pb.Marshal(creator)
	if err != nil {
		return nil, err
	}
	return marshaledIdentity, nil
}

func SetCreator(stub *shimtest.MockStub, creatorMSP string, creatorCert []byte) error {
	marshaledIdentity, err := MarshalIdentity(creatorMSP, creatorCert)
	if err != nil {
		return err
	}
	stub.Creator = marshaledIdentity
	return nil
}

// StubCreate creates mock stub
func StubCreate(t *testing.T) *shimtest.MockStub {
	stub := shimtest.NewMockStub("mockStub", cc.New())
	stub.ChannelID = "acl"
	require.NotNil(t, stub)

	cert, err := GetCert(AdminCertPath)
	require.NoError(t, err)

	err = SetCreator(stub, TestCreatorMSP, cert.Raw)
	require.NoError(t, err)

	return stub
}

// StubCreateAndInit creates mock stub and initializes it with TestIniArgs
func StubCreateAndInit(t *testing.T) *shimtest.MockStub {
	stub := StubCreate(t)
	cfgBytes, err := protojson.Marshal(TestInitConfig)
	require.NoError(t, err)
	var args [][]byte
	args = append(args, cfgBytes)
	rsp := stub.MockInit("0", args)
	require.Equal(t, shim.OK, int(rsp.GetStatus()))

	return stub
}

// GetCert returns certificate located at path
func GetCert(certPath string) (*x509.Certificate, error) {
	if len(certPath) == 0 {
		return nil, errors.New("cert path is empty")
	}

	var certData []byte
	switch certPath {
	case AdminCertPath:
		certData = []byte(AdminCert)
	case UserCertPath:
		certData = []byte(UserCert)
	default:
		return nil, fmt.Errorf("unsupported cert path, %s", certPath)
	}

	pCert, _ := pem.Decode(certData)
	parsed, err := x509.ParseCertificate(pCert.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing cert data failed, err: %w", err)
	}

	return parsed, nil
}

// GenerateTestValidatorSignatures returns test validator signatures
func GenerateTestValidatorSignatures(pKeys []string, digest []byte) (vpKeys [][]byte, vSignatures [][]byte) {
	for i, pubKey := range pKeys {
		sKey, ok := MockValidatorsKeys[pubKey]
		if !ok {
			sKey = DuplicateMockUsersSecretKeys[i]
			fmt.Println(sKey)
		}
		vpKeys = append(vpKeys, []byte(pubKey))
		vSignatures = append(vSignatures, HexEncodedSignature(base58.Decode(sKey), digest))
	}
	return
}

func Base58EncodedSignature(privateKey []byte, message []byte) []byte {
	return []byte(base58.Encode(sign(privateKey, message)))
}

func HexEncodedSignature(privateKey []byte, message []byte) []byte {
	return []byte(hex.EncodeToString(sign(privateKey, message)))
}

func sign(privateKeyBytes []byte, message []byte) []byte {
	if len(privateKeyBytes) == ed25519.PrivateKeySize {
		return ed25519.Sign(privateKeyBytes, message)
	}
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: eth.S256(),
		},
		D: new(big.Int).SetBytes(privateKeyBytes),
	}

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, message)
	if err != nil {
		return nil
	}

	return signature
}

func VerifySignature(
	publicKey []byte,
	message []byte,
	signature []byte,
) bool {
	if verifyEd25519Signature(publicKey, message, signature) {
		return true
	}

	if verifySecp256k1Signature(publicKey, message, signature) {
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
