package unit

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

type seriesSetKyc struct {
	testAddress string
	newKYC      string
	respStatus  int32
	errorMsg    string
}

// add dynamic errorMsg in series
func (s *seriesSetKyc) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestSetKycTrue(t *testing.T) {
	t.Parallel()

	s := &seriesSetKyc{
		testAddress: common.TestAddr,
		newKYC:      "newKychash",
		respStatus:  200,
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setKyc(t, stub, s)
	validationResultSetKyc(t, stub, resp, s)
}

func TestSetKycEmptyAddress(t *testing.T) {
	t.Parallel()

	t.Skip("https://github.com/anoideaopen/acl/-/issues/3")
	s := &seriesSetKyc{
		testAddress: "",
		newKYC:      "newKychash",
		respStatus:  500,
		errorMsg:    errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := setKyc(t, stub, s)
	validationResultSetKyc(t, stub, resp, s)
}

func TestSetKycWrongAddress(t *testing.T) {
	t.Parallel()

	s := &seriesSetKyc{
		testAddress: common.TestWrongAddress,
		newKYC:      "newKychash",
		respStatus:  500,
	}

	errorMsg := "account info for address " +
		s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := setKyc(t, stub, s)
	validationResultSetKyc(t, stub, resp, s)
}

func setKyc(t *testing.T, stub *shimtest.MockStub, ser *seriesSetKyc) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	// change KYC
	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	pKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubKey := range common.MockValidatorKeys {
		pKeys = append(pKeys, pubKey)
	}

	// hashed := sha3.Sum256(base58.Decode(pkey))
	// addr := base58.CheckEncode(hashed[1:], hashed[0])

	message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnSetKYC, ser.testAddress, ser.newKYC, nonce}, pKeys...), "")))

	vPKeys := make([][]byte, 0, len(pKeys))
	vSignatures := make([][]byte, 0, len(pKeys))
	for _, pubKey := range pKeys {
		sKey := common.MockValidatorKeys[pubKey]
		vPKeys = append(vPKeys, []byte(pubKey))
		vSignatures = append(vSignatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(sKey), message[:]))))
	}

	invokeArgs := append(
		append([][]byte{[]byte(common.FnSetKYC), []byte(ser.testAddress), []byte(ser.newKYC), []byte(nonce)}, vPKeys...),
		vSignatures...,
	)
	respNewKey := stub.MockInvoke("0", invokeArgs)

	return respNewKey
}

func validationResultSetKyc(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *seriesSetKyc) {
	require.Equal(t, ser.respStatus, resp.Status)
	require.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	// check address
	check := stub.MockInvoke("0", [][]byte{[]byte(common.FnGetAccInfoFn), []byte(ser.testAddress)})
	require.Equal(t, int32(shim.OK), check.Status)

	addrFromLedger := &pb.AccountInfo{}
	require.NoError(t, json.Unmarshal(check.Payload, addrFromLedger))
	require.Equal(t, false, addrFromLedger.BlackListed)
	require.Equal(t, false, addrFromLedger.GrayListed)
	require.Equal(t, ser.newKYC, addrFromLedger.KycHash)
}
