package cc

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
	pb "gitlab.n-t.io/core/library/go/foundation/v3/proto"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

type serieSetKyc struct {
	testAddress string
	newKYC      string
	respStatus  int32
	errorMsg    string
}

// add dinamyc errorMsg in serie
func (s *serieSetKyc) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestSetKycTrue(t *testing.T) {
	t.Parallel()

	s := &serieSetKyc{
		testAddress: testaddr,
		newKYC:      "newKychash",
		respStatus:  200,
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := setKyc(t, stub, s)
	validationResultSetKyc(t, stub, resp, s)
}

func TestSetKycEmptyAddress(t *testing.T) {
	t.Parallel()

	t.Skip("https://gitlab.n-t.io/core/library/chaincode/acl/-/issues/3")
	s := &serieSetKyc{
		testAddress: "",
		newKYC:      "newKychash",
		respStatus:  500,
		errorMsg:    errorMsgEmptyAddress,
	}

	stub := StubCreate(t)
	resp := setKyc(t, stub, s)
	validationResultSetKyc(t, stub, resp, s)
}

func TestSetKycWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieSetKyc{
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		newKYC:      "newKychash",
		respStatus:  500,
	}

	errorMsg := "Account info for address " +
		s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := setKyc(t, stub, s)
	validationResultSetKyc(t, stub, resp, s)
}

func setKyc(t *testing.T, stub *shimtest.MockStub, ser *serieSetKyc) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	// change KYC
	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	pKeys := make([]string, 0, len(MockValidatorKeys))
	for pubkey := range MockValidatorKeys {
		pKeys = append(pKeys, pubkey)
	}

	// hashed := sha3.Sum256(base58.Decode(pkey))
	// addr := base58.CheckEncode(hashed[1:], hashed[0])

	message := sha3.Sum256([]byte(strings.Join(append([]string{fnSetKYC, ser.testAddress, ser.newKYC, nonce}, pKeys...), "")))

	vPkeys := make([][]byte, 0, len(pKeys))
	vSignatures := make([][]byte, 0, len(pKeys))
	for _, pubkey := range pKeys {
		skey := MockValidatorKeys[pubkey]
		vPkeys = append(vPkeys, []byte(pubkey))
		vSignatures = append(vSignatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(skey), message[:]))))
	}

	invokeArgs := append(
		append([][]byte{[]byte(fnSetKYC), []byte(ser.testAddress), []byte(ser.newKYC), []byte(nonce)}, vPkeys...),
		vSignatures...,
	)
	respNewKey := stub.MockInvoke("0", invokeArgs)

	return respNewKey
}

func validationResultSetKyc(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *serieSetKyc) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	// check address
	check := stub.MockInvoke("0", [][]byte{[]byte(fnGetAccInfoFn), []byte(ser.testAddress)})
	assert.Equal(t, int32(shim.OK), check.Status)

	addrFromLedger := &pb.AccountInfo{}
	assert.NoError(t, json.Unmarshal(check.Payload, addrFromLedger))
	assert.Equal(t, false, addrFromLedger.BlackListed)
	assert.Equal(t, false, addrFromLedger.GrayListed)
	assert.Equal(t, ser.newKYC, addrFromLedger.KycHash)
}
