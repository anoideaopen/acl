package cc

import (
	"encoding/hex"
	"fmt"
	"testing"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

const (
	kycHash    = "kycHash"
	testUserID = "testUserID"
	stateTrue  = "true"
)

type serieAddUser struct {
	testPubKey  string
	testAddress string
	kycHash     string
	testUserID  string
	respStatus  int32
	errorMsg    string
}

// add dinamyc errorMsg in serie
func (s *serieAddUser) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestAddUserPubkeyEqual43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyEqual44Symbols(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		testAddress: "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyEmpty(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
		errorMsg:    "encoded base 58 public key is empty",
	}

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.testPubKey + "'. decoded public key len is 33 but expected 32"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.testPubKey + "'. decoded public key len is 31 but expected 32"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyWrongString(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "AbracadabraAbracadabraAbracadabraAbracada0oI",
		testAddress: "2i1EhJeQG3hyXZiv64XPNAHFhHRPbXFw6Tt6P6ewV4Q98KaKZM",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
		errorMsg:    "",
	}

	s.SetError("failed base58 decoding of key " + s.testPubKey)

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyWrongNumeric(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "01111111111111111111111111111111",
		testAddress: "2CkjXDKfcFFMVdLP9QzBBqFG8PGUxaERwhyvrh4BLsPNwW1T6F",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
		errorMsg:    "",
	}

	s.SetError("failed base58 decoding of key " + s.testPubKey)

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "00000000000000000000000000000000",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyWithSpesialSymbols(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserEmptyKycHash(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  pubkey,
		testAddress: testaddr,
		kycHash:     "",
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
		errorMsg:    "empty kyc hash",
	}

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserEmptyUserID(t *testing.T) {
	t.Parallel()

	s := &serieAddUser{
		testPubKey:  pubkey,
		testAddress: testaddr,
		kycHash:     kycHash,
		testUserID:  "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    "empty userID",
	}

	stub := StubCreate(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserAddExistedUser(t *testing.T) {
	stub := StubCreate(t)

	t.Run("Happy path", func(t *testing.T) {
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte("true")},
		)
		assert.Equal(t, int32(shim.OK), resp.Status)

		// check
		result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(pubkey)})
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AclResponse{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.Address)
		assert.NotNil(t, response.Account)
		assert.Equal(t, testaddr, response.Address.Address.AddrString(), "invalid address")
		assert.Equal(t, kycHash, response.Account.KycHash)
		assert.False(t, response.Account.GrayListed)
		assert.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
		assert.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
		assert.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
	})

	t.Run("Add already existed user (wrong case)", func(t *testing.T) {
		// and add this user again
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
		// check err status
		assert.Equal(t, int32(shim.ERROR), resp.Status)

		// construct addr
		hashed := sha3.Sum256(base58.Decode(pubkey))
		pkeys := hex.EncodeToString(hashed[:])
		addr := base58.CheckEncode(hashed[1:], hashed[0])
		expectedError := fmt.Sprintf("The address %s associated with key %s already exists", addr, pkeys)

		// check err msg
		assert.Error(t, errors.New(resp.Message), expectedError)
	})
}

func addUser(stub *shimtest.MockStub, ser *serieAddUser) peer.Response {
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(ser.testPubKey), []byte(ser.kycHash), []byte(ser.testUserID), []byte(stateTrue)},
	)
	return resp
}

func validationResultAddUser(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *serieAddUser) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(ser.testPubKey)})
	assert.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, ser.testAddress, response.Address.Address.AddrString(), "invalid address")
	assert.Equal(t, ser.kycHash, response.Account.KycHash)
	assert.False(t, response.Account.GrayListed)
	assert.Equal(t, ser.testUserID, response.Address.Address.UserID, "invalid userID")
	assert.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
	assert.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
}
