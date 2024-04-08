package cc

import (
	"testing"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/stretchr/testify/assert"
)

type serieCheckKeys struct {
	testPubKey  string
	testAddress string
	respStatus  int32
	kycHash     string
	testUserID  string
	errorMsg    string
}

// add dinamyc errorMsg in serie
func (s *serieCheckKeys) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestCheckKeysPublicKeyEqual43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		respStatus:  int32(shim.OK),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
		errorMsg:    "",
	}

	checkKeys(t, s)
}

func TestCheckKeysPublicKeyEqual44Symbols(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		testAddress: "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N",
		respStatus:  int32(shim.OK),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
		errorMsg:    "",
	}

	checkKeys(t, s)
}

func TestCheckKeysPublicKeyEmpty(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  "",
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
		errorMsg:    ErrEmptyPubKey,
	}

	checkKeys(t, s)
}

func TestCheckKeysPublicKeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.testPubKey + "'. decoded public key len is 33 but expected 32, input: '" +
		s.testPubKey + "'"
	s.SetError(errorMsg)

	checkKeys(t, s)
}

func TestCheckKeysPublicKeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.testPubKey + "'. decoded public key len is 31 but expected 32, input: '" +
		s.testPubKey + "'"
	s.SetError(errorMsg)

	checkKeys(t, s)
}

func TestCheckKeysWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  "00000000000000000000000000000000",
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey + ", input: '" +
		s.testPubKey + "'"
	s.SetError(errorMsg)

	checkKeys(t, s)
}

func TestCheckKeysWithSpesialSymbols(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey + ", input: '" +
		s.testPubKey + "'"
	s.SetError(errorMsg)

	checkKeys(t, s)
}

func TestCheckKeysWithSpesialSymbol(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  "/",
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
	}

	errorMsg := "empty public key detected, input: '" +
		s.testPubKey + "'"
	s.SetError(errorMsg)

	checkKeys(t, s)
}

func TestCheckKeysDuplicateKeys(t *testing.T) {
	t.Parallel()

	s := &serieCheckKeys{
		testPubKey:  pubkey + "/" + pubkey,
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
	}

	errorMsg := "duplicated public keys, input: '" +
		s.testPubKey + "'"
	s.SetError(errorMsg)

	checkKeys(t, s)
}

func checkKeys(t *testing.T, ser *serieCheckKeys) {
	// add user first
	stub := shimtest.NewMockStub("mockStub", New())
	assert.NotNil(t, stub)
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	err = SetCreator(stub, testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	stub.MockInit("0", testInitArgs)

	valid := true
	// attempt to add a user if we use valid values in the serieCheckKeys structure in test
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(ser.testPubKey), []byte(ser.kycHash), []byte(ser.testUserID), []byte(stateTrue)},
	)
	// if not, we substitute default valid values
	if resp.Status != int32(shim.OK) {
		valid = false
		resp = stub.MockInvoke(
			"0",
			[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
	}
	// then check that the user has been added
	assert.Equal(t, int32(shim.OK), resp.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(ser.testPubKey)})
	assert.Equal(t, ser.respStatus, result.Status)

	assert.Equal(t, ser.errorMsg, result.Message)

	// add field validation only for valid structures
	if valid {
		response := &pb.AclResponse{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.Address)
		assert.NotNil(t, response.Account)
		assert.Equal(t, ser.testAddress, response.Address.Address.AddrString(), "invalid address")
		assert.Equal(t, kycHash, response.Account.KycHash)
		assert.False(t, response.Account.GrayListed)
		assert.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
		assert.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
		assert.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
	}
}
