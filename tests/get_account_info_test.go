package tests

import (
	"encoding/json"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/common"
	"testing"

	pb "github.com/anoideaopen/foundation/proto"
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
		testAddress: common.TestAddr,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := getTestAccountInfo(t, stub, s)
	validationResultGetAccountInfo(t, resp, s)
}

func TestGetAccountInfoEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &serieGetAccountInfo{
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := getTestAccountInfo(t, stub, s)
	validationResultGetAccountInfo(t, resp, s)
}

func TestGetAccountInfoWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieGetAccountInfo{
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := getTestAccountInfo(t, stub, s)
	validationResultGetAccountInfo(t, resp, s)
}

func getTestAccountInfo(t *testing.T, stub *shimtest.MockStub, ser *serieGetAccountInfo) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	resp = stub.MockInvoke("0", [][]byte{[]byte(common.FnGetAccInfoFn), []byte(ser.testAddress)})

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
