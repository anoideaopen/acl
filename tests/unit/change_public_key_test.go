package unit

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
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

type seriesChangePublicKey struct {
	newPubKey  string
	respStatus int32
	errorMsg   string
}

// add dynamic errorMsg in series
func (s *seriesChangePublicKey) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestChangePublicKeyEqual43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangePublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyEqual44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangePublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyEmpty(t *testing.T) {
	t.Parallel()

	s := &seriesChangePublicKey{
		newPubKey:  "",
		respStatus: int32(shim.ERROR),
		errorMsg:   errs.ErrEmptyNewKey,
	}

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangePublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
		respStatus: int32(shim.ERROR),
	}

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d', input: '%s'",
		s.newPubKey,
		33,
		s.newPubKey,
	)
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangePublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
		respStatus: int32(shim.ERROR),
	}

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d', input: '%s'",
		s.newPubKey,
		31,
		s.newPubKey,
	)
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyWrongString(t *testing.T) {
	t.Parallel()

	t.Skip("https://github.com/anoideaopen/acl/-/issues/3")
	s := &seriesChangePublicKey{
		newPubKey:  "AbracadabraAbracadabraAbracadabraAbracadabra",
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyWrongNumeric(t *testing.T) {
	t.Parallel()

	t.Skip("https://github.com/anoideaopen/acl/-/issues/3")
	s := &seriesChangePublicKey{
		newPubKey:  "11111111111111111111111111111111",
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &seriesChangePublicKey{
		newPubKey:  "00000000000000000000000000000000",
		respStatus: int32(shim.ERROR),
	}

	errorMsg := "failed base58 decoding of key " +
		s.newPubKey + ", input: '" + s.newPubKey + "'"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyWithSpecialSymbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangePublicKey{
		newPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		respStatus: int32(shim.ERROR),
	}

	errorMsg := "failed base58 decoding of key " +
		s.newPubKey + ", input: '" + s.newPubKey + "'"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeySameKey(t *testing.T) {
	t.Parallel()

	t.Skip("https://github.com/anoideaopen/acl/-/issues/3")
	s := &seriesChangePublicKey{
		newPubKey:  common.PubKey,
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := common.StubCreateAndInit(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func changePublicKey(t *testing.T, stub *shimtest.MockStub, ser *seriesChangePublicKey) peer.Response {
	// prepare (create pk -> addr and addr -> pk mappings in ACL)
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	// change pk
	pKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubKey := range common.MockValidatorKeys {
		pKeys = append(pKeys, pubKey)
	}

	duplicateKeysString := make([]string, 0, len(pKeys))
	for i, pubKey := range pKeys {
		if i == 2 {
			duplicateKeysString = append(duplicateKeysString, pKeys[i-1]) //nolint:staticcheck
		} else {
			duplicateKeysString = append(duplicateKeysString, pubKey) //nolint:staticcheck
		}
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	reasonID := "1"
	message := sha3.Sum256([]byte(
		strings.Join(
			append([]string{common.FnChangePublicKey, common.TestAddr, common.DefaultReason, reasonID, ser.newPubKey, nonce}, pKeys...),
			""),
	))
	vPKeys, vSignatures := common.GenerateTestValidatorSignatures(pKeys, message[:])

	invokeArgs := append(
		append([][]byte{
			[]byte(common.FnChangePublicKey),
			[]byte(common.TestAddr),
			[]byte(common.DefaultReason),
			[]byte(reasonID),
			[]byte(ser.newPubKey),
			[]byte(nonce),
		}, vPKeys...),
		vSignatures...,
	)
	respNewKey := stub.MockInvoke("0", invokeArgs)

	return respNewKey
}

func validationResultChangePublicKey(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *seriesChangePublicKey) {
	require.Equal(t, ser.respStatus, resp.Status)
	require.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	// check pb.Address
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(ser.newPubKey)})
	require.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.Equal(t, common.TestAddr, response.Address.Address.AddrString(),
		"failed to find address %s by new key %s", common.TestAddr, newPubKey)
	require.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
	require.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
	require.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
	require.Equal(t, common.DefaultReason, response.Address.Reason)
	require.Equal(t, int32(1), response.Address.ReasonId)

	// check signature
	srcArgs := response.Address.SignedTx[0:6]
	pksAndSignatures := response.Address.SignedTx[6:]
	pksOfValidators := pksAndSignatures[:len(pksAndSignatures)/2]
	decodedMessage := sha3.Sum256([]byte(strings.Join(append(srcArgs, pksOfValidators...), "")))
	signaturesOfValidators := pksAndSignatures[len(pksAndSignatures)/2:]

	mockValidatorsPublicKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubKey := range common.MockValidatorKeys {
		mockValidatorsPublicKeys = append(mockValidatorsPublicKeys, pubKey)
	}
	for i, vpk := range pksOfValidators {
		require.True(t, helpers.IsValidator(mockValidatorsPublicKeys, vpk),
			"pk %s does not belong to any validator", vpk)
		decodedSignature, err := hex.DecodeString(signaturesOfValidators[i])
		require.NoError(t, err)
		require.True(t, common.VerifySignature(base58.Decode(vpk), decodedMessage[:], decodedSignature),
			"the signature %s does not match the public key %s", signaturesOfValidators[i], vpk)
	}
}

func TestChangePublicKeyNegatives(t *testing.T) {
	// prepare (create pk -> addr and addr -> pk mappings in ACL)
	stub := common.StubCreateAndInit(t)

	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	// change pk
	pKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubKey := range common.MockValidatorKeys {
		pKeys = append(pKeys, pubKey)
	}

	duplicateKeysString := make([]string, 0, len(pKeys))
	for i, pubKey := range pKeys {
		if i == 2 {
			duplicateKeysString = append(duplicateKeysString, pKeys[i-1])
		} else {
			duplicateKeysString = append(duplicateKeysString, pubKey)
		}
	}

	t.Run("fraud: duplicate signature of validator (wrong case)", func(t *testing.T) {
		nonce := strconv.Itoa(int((time.Now().Unix() + 1) * 1000))
		reasonID := "1"
		message := sha3.Sum256([]byte(
			strings.Join(
				append(
					[]string{common.FnChangePublicKey, common.TestAddr, common.DefaultReason, reasonID, newPubKey, nonce},
					duplicateKeysString...,
				),
				""),
		))
		duplicatePubKeysBytes, duplicateSignatures := common.GenerateTestValidatorSignatures(duplicateKeysString, message[:])

		invokeArgs := append(
			append([][]byte{
				[]byte(common.FnChangePublicKey),
				[]byte(common.TestAddr),
				[]byte(common.DefaultReason),
				[]byte(reasonID),
				[]byte(newPubKey),
				[]byte(nonce),
			}, duplicatePubKeysBytes...),
			duplicateSignatures...)

		respNewKey := stub.MockInvoke("0", invokeArgs)
		require.Equal(t, int32(shim.ERROR), respNewKey.Status)
		require.True(t, strings.Contains(respNewKey.Message, "duplicate validators signatures are not allowed"))
	})

	t.Run("NEGATIVE. Number of pub keys does not match number of signatures", func(t *testing.T) {
		nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
		reasonID := "1"
		message := sha3.Sum256([]byte(strings.Join(append(
			[]string{common.FnChangePublicKey, common.TestAddr, common.DefaultReason, reasonID, newPubKey, nonce}, pKeys...), "")))
		vPKeys, vSignatures := common.GenerateTestValidatorSignatures(pKeys, message[:])

		invokeArgs := append(
			append([][]byte{
				[]byte(common.FnChangePublicKey),
				[]byte(common.TestAddr),
				[]byte(common.DefaultReason),
				[]byte(reasonID),
				[]byte(newPubKey),
				[]byte(nonce),
			}, vPKeys...),
			vSignatures[:len(vSignatures)-1]...,
		)
		respNewKey := stub.MockInvoke("0", invokeArgs)
		require.Equal(t, int32(shim.ERROR), respNewKey.Status)
		require.Equal(t, "uneven number of public keys and signatures provided: 5",
			respNewKey.Message)
	})

	t.Run("NEGATIVE. Incorrect new key input", func(t *testing.T) {
		nonce := strconv.Itoa(int(time.Now().UnixNano() * 1000))
		reason := "because..."
		reasonID := "1"
		message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnChangePublicKey, common.TestAddr, reason, reasonID, "blabla", nonce}, pKeys...), "")))
		vPKeys, vSignatures := common.GenerateTestValidatorSignatures(pKeys, message[:])

		invokeArgs := append(
			append([][]byte{
				[]byte(common.FnChangePublicKey),
				[]byte(common.TestAddr),
				[]byte(reason),
				[]byte(reasonID),
				[]byte("blabla"),
				[]byte(nonce),
			}, vPKeys...),
			vSignatures...,
		)
		respNewKey := stub.MockInvoke("0", invokeArgs)
		require.Equal(t, int32(shim.ERROR), respNewKey.Status)
		require.Equal(t, "failed base58 decoding of key blabla, input: 'blabla'", respNewKey.Message)
	})
}
