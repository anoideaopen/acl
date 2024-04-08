package cc

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

// ACL API Functions
const (
	fnAddUser                        = "addUser"
	fnGetUser                        = "getUser"
	fnAddMultisig                    = "addMultisig"
	fnAddMultisigWithBase58Signature = "addMultisigWithBase58Signature"
	fnAddToList                      = "addToList"
	fnDelFromList                    = "delFromList"
	fnCheckKeys                      = "checkKeys"
	fnGetAccInfoFn                   = "getAccountInfo"
	fnChangePublicKey                = "changePublicKey"
	fnSetKYC                         = "setkyc"
	fnAddAdditionalKey               = "addAdditionalKey"
	fnRemoveAdditionalKey            = "removeAdditionalKey"
)

// Access Matrix ACL API Functions
const (
	fnAddRights       = "addRights"
	fnRemoveRights    = "removeRights"
	fnGetAccOpRight   = "getAccountOperationRight"
	fnGetAccAllRights = "getAccountAllRights"
	fnGetOpAllRights  = "getOperationAllRights"
)

const (
	pubkey         = "aGGiDES6PZsZYz2ncsEXz8mXPxZRhVzMbgJFNAA7EA8"
	testaddr       = "2datxk5TmB1spSNn9enVo11dcpgmUoSBSqCx5cCGoWq8qTbZog"
	testCreatorMSP = "platformMSP"
)

const (
	errorMsgEmptyKey     = "empty new key"
	errorMsgEmptyAddress = "empty address"
	errorMsgNotRecords   = "not found any records"
)

const (
	defaultReason = "because..."
)

var (
	adminCertPath = "admin_cert.pem"
	userCertPath  = "user_cert.pem"

	adminCert = "-----BEGIN CERTIFICATE-----\nMIICSDCCAe6gAwIBAgIQAJwYy5PJAYSC1i0UgVN5bjAKBggqhkjOPQQDAjCBhzEL\nMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG\ncmFuY2lzY28xIzAhBgNVBAoTGmF0b215emUudWF0LmRsdC5hdG9teXplLmNoMSYw\nJAYDVQQDEx1jYS5hdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDAeFw0yMDEwMTMw\nODU2MDBaFw0zMDEwMTEwODU2MDBaMHUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD\nYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ4wDAYDVQQLEwVhZG1p\nbjEpMCcGA1UEAwwgQWRtaW5AYXRvbXl6ZS51YXQuZGx0LmF0b215emUuY2gwWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGQX9IhgjCtd3mYZ9DUszmUgvubepVMPD5\nFlwjCglB2SiWuE2rT/T5tHJsU/Y9ZXFtOOpy/g9tQ/0wxDWwpkbro00wSzAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADArBgNVHSMEJDAigCBSv0ueZaB3qWu/\nAwOtbOjaLd68woAqAklfKKhfu10K+DAKBggqhkjOPQQDAgNIADBFAiEAoKRQLe4U\nFfAAwQs3RCWpevOPq+J8T4KEsYvswKjzfJYCIAs2kOmN/AsVUF63unXJY0k9ktfD\nfAaqNRaboY1Yg1iQ\n-----END CERTIFICATE-----"
	userCert  = "-----BEGIN CERTIFICATE-----\nMIICSDCCAe+gAwIBAgIQAO3rcbDmH/0f1DWQgKhYZTAKBggqhkjOPQQDAjCBhzEL\nMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG\ncmFuY2lzY28xIzAhBgNVBAoTGmF0b215emUudWF0LmRsdC5hdG9teXplLmNoMSYw\nJAYDVQQDEx1jYS5hdG9teXplLnVhdC5kbHQuYXRvbXl6ZS5jaDAeFw0yMDEwMTMw\nODU2MDBaFw0zMDEwMTEwODU2MDBaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpD\nYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQLEwZjbGll\nbnQxKTAnBgNVBAMMIFVzZXIyQGF0b215emUudWF0LmRsdC5hdG9teXplLmNoMFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEch+6dRC3SDIZhCSYNNAYE2T7eONz3m/i\n0oEM+/7VbHUJE+IkwZBmV8aCxC177t4OIcOBZuO4fLijnbgipf1cW6NNMEswDgYD\nVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwKwYDVR0jBCQwIoAgUr9LnmWgd6lr\nvwMDrWzo2i3evMKAKgJJXyioX7tdCvgwCgYIKoZIzj0EAwIDRwAwRAIgV71buT7/\n2j+dznSFP1es5KJd1c5IANDzjR9cP5qd/kICIGTjJO5rcOv322nPWaTWr5XUtR3R\n/K0Elk9CQQBTzfqY\n-----END CERTIFICATE-----"
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

func marshalIdentity(creatorMSP string, creatorCert []byte) ([]byte, error) {
	pemblock := &pem.Block{Type: "CERTIFICATE", Bytes: creatorCert}
	pemBytes := pem.EncodeToMemory(pemblock)
	if pemBytes == nil {
		return nil, errors.New("encoding of identity failed")
	}

	creator := &msp.SerializedIdentity{Mspid: creatorMSP, IdBytes: pemBytes}
	marshaledIdentity, err := proto.Marshal(creator)
	if err != nil {
		return nil, err
	}
	return marshaledIdentity, nil
}

func SetCreator(stub *shimtest.MockStub, creatorMSP string, creatorCert []byte) error {
	marshaledIdentity, err := marshalIdentity(creatorMSP, creatorCert)
	if err != nil {
		return err
	}
	stub.Creator = marshaledIdentity
	return nil
}

func StubCreate(t *testing.T) *shimtest.MockStub {
	stub := shimtest.NewMockStub("mockStub", New())
	stub.ChannelID = "acl"
	assert.NotNil(t, stub)

	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)

	err = SetCreator(stub, testCreatorMSP, cert.Raw)
	assert.NoError(t, err)

	rsp := stub.MockInit("0", testInitArgs)
	assert.Equal(t, shim.OK, int(rsp.Status))

	return stub
}

func getCert(certPath string) (*x509.Certificate, error) {
	if len(certPath) == 0 {
		return nil, fmt.Errorf("cert path is empty")
	}

	var certData []byte
	switch certPath {
	case adminCertPath:
		certData = []byte(adminCert)
	case userCertPath:
		certData = []byte(userCert)
	default:
		return nil, fmt.Errorf("unsupported cert path, %s", certPath)
	}

	pcert, _ := pem.Decode(certData)
	parsed, err := x509.ParseCertificate(pcert.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing cert data failed, err: %w", err)
	}

	return parsed, nil
}

func generateTestValidatorSignatures(pKeys []string, digest []byte) (vPkeys [][]byte, vSignatures [][]byte) {
	for i, pubkey := range pKeys {
		skey, ok := MockValidatorKeys[pubkey]
		if !ok {
			skey = DuplicateMockValidatorsSecretKeys[i]
			fmt.Println(skey)
		}
		vPkeys = append(vPkeys, []byte(pubkey))
		vSignatures = append(vSignatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(skey), digest))))
	}
	return
}
