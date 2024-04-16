package common

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/proto"
	"github.com/btcsuite/btcutil/base58"
	pb "github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

var TestAdminSKI = []byte("dc752d6afb51c33327b7873fdb08adb91de15ee7c88f4f9949445aeeb8ea4e99")

var TestValidators = []string{
	"A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4",
	"5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5",
	"6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4",
}

var TestValidatorsBytes = [][]byte{
	[]byte(TestValidators[0]),
	[]byte(TestValidators[1]),
	[]byte(TestValidators[2]),
}

var TestInitArgs = append(
	[][]byte{
		TestAdminSKI,
		[]byte(strconv.Itoa(len(TestValidatorsBytes))),
	},
	TestValidatorsBytes...)

var TestInitConfig = &proto.ACLConfig{
	CCName:          "acl",
	AdminSKI:        TestAdminSKI,
	ValidatorsCount: int64(len(TestValidators)),
	Validators:      TestValidators,
}

// ACL API Functions
const (
	FnAddUser                        = "addUser"
	FnGetUser                        = "getUser"
	FnAddMultisig                    = "addMultisig"
	FnAddMultisigWithBase58Signature = "addMultisigWithBase58Signature"
	FnAddToList                      = "addToList"
	FnDelFromList                    = "delFromList"
	FnCheckKeys                      = "checkKeys"
	FnGetAccInfoFn                   = "getAccountInfo"
	FnChangePublicKey                = "changePublicKey"
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
	PubKey         = "aGGiDES6PZsZYz2ncsEXz8mXPxZRhVzMbgJFNAA7EA8"
	TestAddr       = "2datxk5TmB1spSNn9enVo11dcpgmUoSBSqCx5cCGoWq8qTbZog"
	TestCreatorMSP = "platformMSP"
)

const (
	DefaultReason = "because..."
)

var (
	AdminCertPath = "admin_cert.pem"
	UserCertPath  = "user_cert.pem"

	AdminCert = "-----BEGIN CERTIFICATE-----\nMIICSDCCAe6gAwIBAgIQAJwYy5PJAYSC1i0UgVN5bjAKBggqhkjOPQQDAjCBhzEL\nMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG\ncmFuY2lzY28xIzAhBgNVBAoTGmF0b215emUudWF0LmRsdC5hdG9teXplLmNoMSYw\nJAYDVQQDEx1jYS5hdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDAeFw0yMDEwMTMw\nODU2MDBaFw0zMDEwMTEwODU2MDBaMHUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD\nYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ4wDAYDVQQLEwVhZG1p\nbjEpMCcGA1UEAwwgQWRtaW5AYXRvbXl6ZS51YXQuZGx0LmF0b215emUuY2gwWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGQX9IhgjCtd3mYZ9DUszmUgvubepVMPD5\nFlwjCglB2SiWuE2rT/T5tHJsU/Y9ZXFtOOpy/g9tQ/0wxDWwpkbro00wSzAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADArBgNVHSMEJDAigCBSv0ueZaB3qWu/\nAwOtbOjaLd68woAqAklfKKhfu10K+DAKBggqhkjOPQQDAgNIADBFAiEAoKRQLe4U\nFfAAwQs3RCWpevOPq+J8T4KEsYvswKjzfJYCIAs2kOmN/AsVUF63unXJY0k9ktfD\nfAaqNRaboY1Yg1iQ\n-----END CERTIFICATE-----"
	UserCert  = "-----BEGIN CERTIFICATE-----\nMIICSDCCAe+gAwIBAgIQAO3rcbDmH/0f1DWQgKhYZTAKBggqhkjOPQQDAjCBhzEL\nMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG\ncmFuY2lzY28xIzAhBgNVBAoTGmF0b215emUudWF0LmRsdC5hdG9teXplLmNoMSYw\nJAYDVQQDEx1jYS5hdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDAeFw0yMDEwMTMw\nODU2MDBaFw0zMDEwMTEwODU2MDBaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD\nYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQLEwZjbGll\nbnQxKTAnBgNVBAMMIFVzZXIyQGF0b215emUudWF0LmRsdC5hdG9teXplLmNoMFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEch+6dRC3SDIZhCSYNNAYE2T7eONz3m/i\n0oEM+/7VbHUJE+IkwZBmV8aCxC177t4OIcOBZuO4fLijnbgipf1cW6NNMEswDgYD\nVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwKwYDVR0jBCQwIoAgUr9LnmWgd6lr\nvwMDrWzo2i3evMKAKgJJXyioX7tdCvgwCgYIKoZIzj0EAwIDRwAwRAIgV71buT7/\n2j+dznSFP1es5KJd1c5IANDzjR9cP5qd/kICIGTjJO5rcOv322nPWaTWr5XUtR3R\n/K0Elk9CQQBTzfqY\n-----END CERTIFICATE-----"
)

const (
	TestWrongAddress = "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt"
)

// MockValidatorKeys stores pubkey -> secret key mapping
var MockValidatorKeys = map[string]string{
	"A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4": "3aDebSkgXq37VPrzThboaV8oMMbYXrRAt7hnGrod4PNMnGfXjh14TY7cQs8eVT46C4RK4ZyNKLrBmyD5CYZiFmkr",
	"5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5": "5D2BpuHZwik9zPFuaqba4zbvNP8TB7PQ6usZke5bufPbKf8xG6ZMHReBqwKw9aDfpTaNfaRsg1j2zVZWrX8hg18D",
	"6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4": "3sK2wHWxU58kzAeFtShDMsPm5Qh74NAWgfwCmdKyzvp4npivEDDEp14WgQpg7KGaVNF7qWyyMvkKPzGddVkxagNN",
}

var DuplicateMockValidatorsSecretKeys = []string{
	"3aDebSkgXq37VPrzThboaV8oMMbYXrRAt7hnGrod4PNMnGfXjh14TY7cQs8eVT46C4RK4ZyNKLrBmyD5CYZiFmkr",
	"5D2BpuHZwik9zPFuaqba4zbvNP8TB7PQ6usZke5bufPbKf8xG6ZMHReBqwKw9aDfpTaNfaRsg1j2zVZWrX8hg18D",
	"5D2BpuHZwik9zPFuaqba4zbvNP8TB7PQ6usZke5bufPbKf8xG6ZMHReBqwKw9aDfpTaNfaRsg1j2zVZWrX8hg18D",
	"5D2BpuHZwik9zPFuaqba4zbvNP8TB7PQ6usZke5bufPbKf8xG6ZMHReBqwKw9aDfpTaNfaRsg1j2zVZWrX8hg18D",
}

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
	assert.NotNil(t, stub)

	cert, err := GetCert(AdminCertPath)
	assert.NoError(t, err)

	err = SetCreator(stub, TestCreatorMSP, cert.Raw)
	assert.NoError(t, err)

	return stub
}

// StubCreateAndInit creates mock stub and initializes it with TestIniArgs
func StubCreateAndInit(t *testing.T) *shimtest.MockStub {
	stub := StubCreate(t)
	rsp := stub.MockInit("0", TestInitArgs)
	assert.Equal(t, shim.OK, int(rsp.Status))

	return stub
}

// GetCert returns certificate located at path
func GetCert(certPath string) (*x509.Certificate, error) {
	if len(certPath) == 0 {
		return nil, fmt.Errorf("cert path is empty")
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
		sKey, ok := MockValidatorKeys[pubKey]
		if !ok {
			sKey = DuplicateMockValidatorsSecretKeys[i]
			fmt.Println(sKey)
		}
		vpKeys = append(vpKeys, []byte(pubKey))
		vSignatures = append(vSignatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(sKey), digest))))
	}
	return
}
