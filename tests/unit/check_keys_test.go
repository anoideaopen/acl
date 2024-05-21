package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
)

type seriesCheckKeys struct {
	testPubKey  string
	testAddress string
	respStatus  int32
	kycHash     string
	testUserID  string
	errorMsg    string
}

// add dynamic errorMsg in series
func (s *seriesCheckKeys) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestCheckKeysPublicKeyEqual43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesCheckKeys{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		testAddress: common.TestWrongAddress,
		respStatus:  int32(shim.OK),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
		errorMsg:    "",
	}

	checkKeys(t, s)
}

func TestCheckKeysPublicKeyEqual44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesCheckKeys{
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

	s := &seriesCheckKeys{
		testPubKey:  "",
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		kycHash:     "kycHash",
		testUserID:  "testUserID",
		errorMsg:    errs.ErrEmptyPubKey,
	}

	checkKeys(t, s)
}

func TestCheckKeysPublicKeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesCheckKeys{
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

	s := &seriesCheckKeys{
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

	s := &seriesCheckKeys{
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

func TestCheckKeysWithSpecialSymbols(t *testing.T) {
	t.Parallel()

	s := &seriesCheckKeys{
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

func TestCheckKeysWithSpecialSymbol(t *testing.T) {
	t.Parallel()

	s := &seriesCheckKeys{
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

	s := &seriesCheckKeys{
		testPubKey:  common.PubKey + "/" + common.PubKey,
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

func checkKeys(t *testing.T, ser *seriesCheckKeys) {
	// add user first
	stub := common.StubCreateAndInit(t)

	valid := true
	// attempt to add a user if we use valid values in the seriesCheckKeys structure in test
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(ser.testPubKey), []byte(ser.kycHash), []byte(ser.testUserID), []byte(stateTrue)},
	)
	// if not, we substitute default valid values
	if resp.Status != int32(shim.OK) {
		valid = false
		resp = stub.MockInvoke(
			"0",
			[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
	}
	// then check that the user has been added
	require.Equal(t, int32(shim.OK), resp.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(ser.testPubKey)})
	require.Equal(t, ser.respStatus, result.Status)

	require.Equal(t, ser.errorMsg, result.Message)

	// add field validation only for valid structures
	if valid {
		response := &pb.AclResponse{}
		require.NoError(t, proto.Unmarshal(result.Payload, response))
		require.NotNil(t, response.Address)
		require.NotNil(t, response.Account)
		require.Equal(t, ser.testAddress, response.Address.Address.AddrString(), "invalid address")
		require.Equal(t, kycHash, response.Account.KycHash)
		require.False(t, response.Account.GrayListed)
		require.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
		require.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
		require.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
	}
}
