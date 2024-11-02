package unit

import (
	"encoding/json"
	"testing"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
)

type seriesGetAccountInfo struct {
	testAddress string
	respStatus  int32
	errorMsg    string
}

// add dynamic errorMsg in series
func (s *seriesGetAccountInfo) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestGetAccountInfoTrue(t *testing.T) {
	t.Parallel()

	s := &seriesGetAccountInfo{
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

	s := &seriesGetAccountInfo{
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

	s := &seriesGetAccountInfo{
		testAddress: common.TestWrongAddress,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := getTestAccountInfo(t, stub, s)
	validationResultGetAccountInfo(t, resp, s)
}

func getTestAccountInfo(t *testing.T, stub *shimtest.MockStub, ser *seriesGetAccountInfo) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	resp = stub.MockInvoke("0", [][]byte{[]byte(common.FnGetAccInfoFn), []byte(ser.testAddress)})

	return resp
}

func validationResultGetAccountInfo(t *testing.T, resp peer.Response, ser *seriesGetAccountInfo) {
	require.Equal(t, ser.respStatus, resp.Status)
	require.Contains(t, resp.Message, ser.errorMsg)

	if resp.Status != int32(shim.OK) {
		return
	}

	addrFromLedger := &pb.AccountInfo{}
	require.NoError(t, json.Unmarshal(resp.Payload, addrFromLedger))
	require.Equal(t, false, addrFromLedger.BlackListed)
	require.Equal(t, false, addrFromLedger.GrayListed)
	require.Equal(t, kycHash, addrFromLedger.KycHash)
}
