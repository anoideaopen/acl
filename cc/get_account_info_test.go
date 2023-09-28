package cc

import (
	"encoding/json"
	"testing"

	pb "github.com/atomyze-foundation/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
)

type serieGetAccountInfo struct {
	testAddress string
	respStatus  int32
	errorMsg    string
}

// add dinamyc errorMsg in serie
func (s *serieGetAccountInfo) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestGetAccountInfoTrue(t *testing.T) {
	t.Parallel()

	s := &serieGetAccountInfo{
		testAddress: testaddr,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := getTestAccountInfo(t, stub, s)
	validationResultGetAccountInfo(t, resp, s)
}

func TestGetAccountInfoEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &serieGetAccountInfo{
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    errorMsgEmptyAddress,
	}

	stub := StubCreate(t)
	resp := getTestAccountInfo(t, stub, s)
	validationResultGetAccountInfo(t, resp, s)
}

func TestGetAccountInfoWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieGetAccountInfo{
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "Account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := getTestAccountInfo(t, stub, s)
	validationResultGetAccountInfo(t, resp, s)
}

func getTestAccountInfo(t *testing.T, stub *shimtest.MockStub, ser *serieGetAccountInfo) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	resp = stub.MockInvoke("0", [][]byte{[]byte(fnGetAccInfoFn), []byte(ser.testAddress)})

	return resp
}

func validationResultGetAccountInfo(t *testing.T, resp peer.Response, ser *serieGetAccountInfo) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	addrFromLedger := &pb.AccountInfo{}
	assert.NoError(t, json.Unmarshal(resp.Payload, addrFromLedger))
	assert.Equal(t, false, addrFromLedger.BlackListed)
	assert.Equal(t, false, addrFromLedger.GrayListed)
	assert.Equal(t, kycHash, addrFromLedger.KycHash)
}
