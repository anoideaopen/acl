package unit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

const (
	kycHash    = "kycHash"
	testUserID = "testUserID"
	stateTrue  = "true"
)

type seriesAddUser struct {
	testPubKey     string
	testAddress    string
	kycHash        string
	testUserID     string
	testPubKeyType string
	respStatus     int32
	errorMsg       string
}

// add dynamic errorMsg in series
func (s *seriesAddUser) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestAddUserPubKeyEqual43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		testAddress: common.TestWrongAddress,
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubKeyEqual44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		testAddress: "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubKeyEmpty(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
		errorMsg:    "encoded base 58 public key is empty",
	}

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubkeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d'",
		s.testPubKey,
		33,
	)
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubKeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d'",
		s.testPubKey,
		31,
	)
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubKeyWrongString(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "AbracadabraAbracadabraAbracadabraAbracada0oI",
		testAddress: "2i1EhJeQG3hyXZiv64XPNAHFhHRPbXFw6Tt6P6ewV4Q98KaKZM",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
		errorMsg:    "",
	}

	s.SetError("failed base58 decoding of key " + s.testPubKey)

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubKeyWrongNumeric(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "01111111111111111111111111111111",
		testAddress: "2CkjXDKfcFFMVdLP9QzBBqFG8PGUxaERwhyvrh4BLsPNwW1T6F",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
		errorMsg:    "",
	}

	s.SetError("failed base58 decoding of key " + s.testPubKey)

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubKeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "00000000000000000000000000000000",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserPubKeyWithSpecialSymbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		testAddress: "",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserEmptyKycHash(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  common.PubKey,
		testAddress: common.TestAddr,
		kycHash:     "",
		testUserID:  testUserID,
		respStatus:  int32(shim.ERROR),
		errorMsg:    "empty kyc hash",
	}

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserEmptyUserID(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  common.PubKey,
		testAddress: common.TestAddr,
		kycHash:     kycHash,
		testUserID:  "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    "empty userID",
	}

	stub := common.StubCreateAndInit(t)
	resp := addUser(stub, s)
	validationResultAddUser(t, stub, resp, s)
}

func TestAddUserAddExistedUser(t *testing.T) {
	stub := common.StubCreateAndInit(t)

	t.Run("Happy path", func(t *testing.T) {
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte("true")},
		)
		require.Equal(t, int32(shim.OK), resp.Status)

		// check
		result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AclResponse{}
		require.NoError(t, proto.Unmarshal(result.Payload, response))
		require.NotNil(t, response.Address)
		require.NotNil(t, response.Account)
		require.Equal(t, common.TestAddr, response.Address.Address.AddrString(), "invalid address")
		require.Equal(t, kycHash, response.Account.KycHash)
		require.False(t, response.Account.GrayListed)
		require.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
		require.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
		require.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
	})

	t.Run("Add already existed user (wrong case)", func(t *testing.T) {
		// and add this user again
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
		// check err status
		require.Equal(t, int32(shim.ERROR), resp.Status)

		// construct addr
		hashed := sha3.Sum256(base58.Decode(common.PubKey))
		pKeys := hex.EncodeToString(hashed[:])
		addr := base58.CheckEncode(hashed[1:], hashed[0])
		expectedError := fmt.Sprintf("The address %s associated with key %s already exists", addr, pKeys)

		// check err msg
		require.Error(t, errors.New(resp.Message), expectedError)
	})
}

func addUser(stub *shimtest.MockStub, ser *seriesAddUser) peer.Response {
	invokeArgs := [][]byte{
		[]byte(common.FnAddUser),
		[]byte(ser.testPubKey),
		[]byte(ser.kycHash),
		[]byte(ser.testUserID),
		[]byte(stateTrue),
	}
	resp := stub.MockInvoke("0", invokeArgs)
	return resp
}

func addUserWithPublicKeyType(stub *shimtest.MockStub, ser *seriesAddUser) peer.Response {
	invokeArgs := [][]byte{
		[]byte(common.FnAddUserWithPublicKeyType),
		[]byte(ser.testPubKey),
		[]byte(ser.kycHash),
		[]byte(ser.testUserID),
		[]byte(stateTrue),
		[]byte(ser.testPubKeyType),
	}
	resp := stub.MockInvoke("0", invokeArgs)
	return resp
}

func validationResultAddUser(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *seriesAddUser) {
	require.Equal(t, ser.respStatus, resp.Status)
	require.Contains(t, resp.Message, ser.errorMsg)

	if resp.Status != int32(shim.OK) {
		return
	}

	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(ser.testPubKey)})
	require.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.NotNil(t, response.Account)
	require.Equal(t, ser.testAddress, response.Address.Address.AddrString(), "invalid address")
	require.Equal(t, ser.kycHash, response.Account.KycHash)
	require.False(t, response.Account.GrayListed)
	require.Equal(t, ser.testUserID, response.Address.Address.UserID, "invalid userID")
	require.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
	require.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
}
