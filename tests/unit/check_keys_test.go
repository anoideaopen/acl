package unit

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type seriesCheckKeys struct {
	testPubKey  string
	testPrivKey string
	testAddress string
	respStatus  int32
	kycHash     string
	testUserID  string
	errorMsg    string
	keyTypes    []pb.KeyType
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
		keyTypes:    []pb.KeyType{pb.KeyType_ed25519},
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
		keyTypes:    []pb.KeyType{pb.KeyType_ed25519},
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

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d', input: '%s'",
		s.testPubKey,
		33,
		s.testPubKey,
	)
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

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d', input: '%s'",
		s.testPubKey,
		31,
		s.testPubKey,
	)
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

	errorMsg := "encoded base 58 public key is empty, input: '" +
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

	errorMsg := "duplicated public keys"
	s.SetError(errorMsg)

	checkKeys(t, s)
}

func TestCheckKeys(t *testing.T) {
	t.Parallel()

	s := &seriesCheckKeys{
		testPubKey: common.TestUsers[0].PublicKey + "/" +
			common.TestUsers[1].PublicKey + "/" +
			common.TestUsers[2].PublicKey,
		testPrivKey: common.TestUsers[0].PrivateKey + "/" +
			common.TestUsers[1].PrivateKey + "/" +
			common.TestUsers[2].PrivateKey,
		testAddress: "K7n4n5Pn8r6EK83UaUnzk56DLoGywjYQfYxM4hVVSp9sBau42",
		respStatus:  int32(shim.OK),
		kycHash:     kycHash,
		testUserID:  testUserID,
		keyTypes: []pb.KeyType{
			pb.KeyType(pb.KeyType_value[common.TestUsers[0].KeyType]),
			pb.KeyType(pb.KeyType_value[common.TestUsers[1].KeyType]),
			pb.KeyType(pb.KeyType_value[common.TestUsers[2].KeyType]),
		},
	}

	checkMultiKeys(t, s)
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

	require.Contains(t, result.Message, ser.errorMsg)

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
		require.Equal(t, len(ser.keyTypes), len(response.KeyTypes))
		for i := range ser.keyTypes {
			require.Equal(t, ser.keyTypes[i], response.KeyTypes[i])
		}
	}
}

func checkMultiKeys(t *testing.T, ser *seriesCheckKeys) {
	const keyDelimiter = "/"
	// add user first
	stub := common.StubCreateAndInit(t)

	pubKeys := strings.Split(ser.testPubKey, keyDelimiter)
	privateKeys := strings.Split(ser.testPrivKey, keyDelimiter)

	for _, key := range pubKeys {
		resp := stub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnAddUser),
				[]byte(key),
				[]byte(kycHash),
				[]byte(testUserID),
				[]byte(stateTrue),
			},
		)
		require.Equal(t, int32(shim.OK), resp.Status)
	}

	pubKeysBytes := make([][]byte, 0, len(pubKeys))
	for _, pubKey := range pubKeys {
		pubKeysBytes = append(pubKeysBytes, []byte(pubKey))
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisig, strconv.Itoa(len(pubKeys)), nonce}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privateKeys))
	for _, privateKey := range privateKeys {
		signatures = append(signatures, common.HexEncodedSignature(base58.Decode(privateKey), message[:]))
	}

	resp := stub.MockInvoke(
		"0",
		append(append(
			append([][]byte{},
				[]byte(common.FnAddMultisig),
				[]byte(strconv.Itoa(len(pubKeys))),
				[]byte(nonce)),
			pubKeysBytes...,
		), signatures...),
	)
	// then check that the user has been added
	require.Equal(t, int32(shim.OK), resp.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(ser.testPubKey)})
	require.Equal(t, ser.respStatus, result.Status)

	require.Contains(t, result.Message, ser.errorMsg)

	// add field validation only for valid structures
	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.NotNil(t, response.Account)
	require.Equal(t, ser.testAddress, response.Address.Address.AddrString(), "invalid address")
	require.Equal(t, kycHash, response.Account.KycHash)
	require.False(t, response.Account.GrayListed)
	require.Equal(t, "", response.Address.Address.UserID, "invalid userID")
	require.Equal(t, false, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
	require.Equal(t, true, response.Address.Address.IsMultisig, "invalid IsMultisig field")
	require.Equal(t, len(ser.keyTypes), len(response.KeyTypes))
	for i := range ser.keyTypes {
		require.Equal(t, ser.keyTypes[i], response.KeyTypes[i])
	}
}
