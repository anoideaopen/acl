package cc

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

type serieChangePublicKey struct {
	newPubKey  string
	respStatus int32
	errorMsg   string
}

// add dinamyc errorMsg in serie
func (s *serieChangePublicKey) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestChangePublicKeyEqual43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieChangePublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyEqual44Symbols(t *testing.T) {
	t.Parallel()

	s := &serieChangePublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyEmpty(t *testing.T) {
	t.Parallel()

	s := &serieChangePublicKey{
		newPubKey:  "",
		respStatus: int32(shim.ERROR),
		errorMsg:   errorMsgEmptyKey,
	}

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &serieChangePublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
		respStatus: int32(shim.ERROR),
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.newPubKey + "'. decoded public key len is 33 but expected 32, input: '" + s.newPubKey + "'"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieChangePublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
		respStatus: int32(shim.ERROR),
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.newPubKey + "'. decoded public key len is 31 but expected 32, input: '" + s.newPubKey + "'"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyWrongString(t *testing.T) {
	t.Parallel()

	t.Skip("https://github.com/anoideaopen/acl/-/issues/3")
	s := &serieChangePublicKey{
		newPubKey:  "AbracadabraAbracadabraAbracadabraAbracadabra",
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyWrongNumeric(t *testing.T) {
	t.Parallel()

	t.Skip("https://github.com/anoideaopen/acl/-/issues/3")
	s := &serieChangePublicKey{
		newPubKey:  "11111111111111111111111111111111",
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &serieChangePublicKey{
		newPubKey:  "00000000000000000000000000000000",
		respStatus: int32(shim.ERROR),
	}

	errorMsg := "failed base58 decoding of key " +
		s.newPubKey + ", input: '" + s.newPubKey + "'"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeyWithSpesialSymbols(t *testing.T) {
	t.Parallel()

	s := &serieChangePublicKey{
		newPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		respStatus: int32(shim.ERROR),
	}

	errorMsg := "failed base58 decoding of key " +
		s.newPubKey + ", input: '" + s.newPubKey + "'"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func TestChangePublicKeySameKey(t *testing.T) {
	t.Parallel()

	t.Skip("https://github.com/anoideaopen/acl/-/issues/3")
	s := &serieChangePublicKey{
		newPubKey:  pubkey,
		respStatus: int32(shim.OK),
		errorMsg:   "",
	}

	stub := StubCreate(t)
	resp := changePublicKey(t, stub, s)
	validationResultChangePublicKey(t, stub, resp, s)
}

func changePublicKey(t *testing.T, stub *shimtest.MockStub, ser *serieChangePublicKey) peer.Response {
	// prepare (create pk -> addr and addr -> pk mappings in ACL)
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	// change pk
	pKeys := make([]string, 0, len(MockValidatorKeys))
	for pubkey := range MockValidatorKeys {
		pKeys = append(pKeys, pubkey)
	}

	duplicateKeysString := make([]string, 0, len(pKeys))
	for i, pubkey := range pKeys {
		if i == 2 {
			duplicateKeysString = append(duplicateKeysString, pKeys[i-1]) //nolint:staticcheck
		} else {
			duplicateKeysString = append(duplicateKeysString, pubkey) //nolint:staticcheck
		}
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	reasonID := "1"
	message := sha3.Sum256([]byte(
		strings.Join(
			append([]string{fnChangePublicKey, testaddr, defaultReason, reasonID, ser.newPubKey, nonce}, pKeys...),
			""),
	))
	vPkeys, vSignatures := generateTestValidatorSignatures(pKeys, message[:])

	invokeArgs := append(
		append([][]byte{
			[]byte(fnChangePublicKey),
			[]byte(testaddr),
			[]byte(defaultReason),
			[]byte(reasonID),
			[]byte(ser.newPubKey),
			[]byte(nonce),
		}, vPkeys...),
		vSignatures...,
	)
	respNewKey := stub.MockInvoke("0", invokeArgs)

	return respNewKey
}

func validationResultChangePublicKey(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *serieChangePublicKey) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	// check pb.Address
	result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(ser.newPubKey)})
	assert.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.Equal(t, testaddr, response.Address.Address.AddrString(),
		"failed to find address %s by new key %s", testaddr, newPubKey)
	assert.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
	assert.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
	assert.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
	assert.Equal(t, defaultReason, response.Address.Reason)
	assert.Equal(t, int32(1), response.Address.ReasonId)

	// check signature
	srcArgs := response.Address.SignedTx[0:6]
	pksAndSignatures := response.Address.SignedTx[6:]
	pksOfValidators := pksAndSignatures[:len(pksAndSignatures)/2]
	decodedMessage := sha3.Sum256([]byte(strings.Join(append(srcArgs, pksOfValidators...), "")))
	signaturesOfValidators := pksAndSignatures[len(pksAndSignatures)/2:]

	mockValidatorsPublicKeys := make([]string, 0, len(MockValidatorKeys))
	for pubkey := range MockValidatorKeys {
		mockValidatorsPublicKeys = append(mockValidatorsPublicKeys, pubkey)
	}
	for i, vpk := range pksOfValidators {
		assert.True(t, IsValidator(mockValidatorsPublicKeys, vpk),
			"pk %s does not belong to any validator", vpk)
		decodedSignature, err := hex.DecodeString(signaturesOfValidators[i])
		assert.NoError(t, err)
		assert.True(t, ed25519.Verify(base58.Decode(vpk), decodedMessage[:], decodedSignature),
			"the signature %s does not match the public key %s", signaturesOfValidators[i], vpk)
	}
}

func TestChangePublicKeyNegatives(t *testing.T) {
	// prepare (create pk -> addr and addr -> pk mappings in ACL)
	stub := shimtest.NewMockStub("mockStub", New())
	assert.NotNil(t, stub)
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	err = SetCreator(stub, testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	stub.MockInit("0", testInitArgs)

	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	// change pk
	pKeys := make([]string, 0, len(MockValidatorKeys))
	for pubkey := range MockValidatorKeys {
		pKeys = append(pKeys, pubkey)
	}

	duplicateKeysString := make([]string, 0, len(pKeys))
	for i, pubkey := range pKeys {
		if i == 2 {
			duplicateKeysString = append(duplicateKeysString, pKeys[i-1])
		} else {
			duplicateKeysString = append(duplicateKeysString, pubkey)
		}
	}

	t.Run("fraud: duplicate signature of validator (wrong case)", func(t *testing.T) {
		nonce := strconv.Itoa(int((time.Now().Unix() + 1) * 1000))
		reasonID := "1"
		message := sha3.Sum256([]byte(
			strings.Join(
				append(
					[]string{fnChangePublicKey, testaddr, defaultReason, reasonID, newPubKey, nonce},
					duplicateKeysString...,
				),
				""),
		))
		duplicatePubKeysBytes, duplicateSignatures := generateTestValidatorSignatures(duplicateKeysString, message[:])

		invokeArgs := append(
			append([][]byte{
				[]byte(fnChangePublicKey),
				[]byte(testaddr),
				[]byte(defaultReason),
				[]byte(reasonID),
				[]byte(newPubKey),
				[]byte(nonce),
			}, duplicatePubKeysBytes...),
			duplicateSignatures...)

		respNewKey := stub.MockInvoke("0", invokeArgs)
		assert.Equal(t, int32(shim.ERROR), respNewKey.Status)
		assert.True(t, strings.Contains(respNewKey.Message, "duplicate validators signatures are not allowed"))
	})

	t.Run("NEGATIVE. Number of pub keys does not match number of signatures", func(t *testing.T) {
		nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
		reasonID := "1"
		message := sha3.Sum256([]byte(strings.Join(append(
			[]string{fnChangePublicKey, testaddr, defaultReason, reasonID, newPubKey, nonce}, pKeys...), "")))
		vPkeys, vSignatures := generateTestValidatorSignatures(pKeys, message[:])

		invokeArgs := append(
			append([][]byte{
				[]byte(fnChangePublicKey),
				[]byte(testaddr),
				[]byte(defaultReason),
				[]byte(reasonID),
				[]byte(newPubKey),
				[]byte(nonce),
			}, vPkeys...),
			vSignatures[:len(vSignatures)-1]...,
		)
		respNewKey := stub.MockInvoke("0", invokeArgs)
		assert.Equal(t, int32(shim.ERROR), respNewKey.Status)
		assert.Equal(t, "uneven number of public keys and signatures provided: 5",
			respNewKey.Message)
	})

	t.Run("NEGATIVE. Incorrect new key input", func(t *testing.T) {
		nonce := strconv.Itoa(int(time.Now().UnixNano() * 1000))
		reason := "because..."
		reasonID := "1"
		message := sha3.Sum256([]byte(strings.Join(append([]string{fnChangePublicKey, testaddr, reason, reasonID, "blabla", nonce}, pKeys...), "")))
		vPkeys, vSignatures := generateTestValidatorSignatures(pKeys, message[:])

		invokeArgs := append(
			append([][]byte{
				[]byte(fnChangePublicKey),
				[]byte(testaddr),
				[]byte(reason),
				[]byte(reasonID),
				[]byte("blabla"),
				[]byte(nonce),
			}, vPkeys...),
			vSignatures...,
		)
		respNewKey := stub.MockInvoke("0", invokeArgs)
		assert.Equal(t, int32(shim.ERROR), respNewKey.Status)
		assert.Equal(t, "failed base58 decoding of key blabla, input: 'blabla'", respNewKey.Message)
	})
}
