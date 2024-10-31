package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
)

type seriesGrayList struct {
	testAddress string
	respStatus  int32
	errorMsg    string
}

// add dynamic errorMsg in series
func (s *seriesGrayList) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestGrayListTrue(t *testing.T) {
	t.Parallel()

	s := &seriesGrayList{
		testAddress: common.TestAddr,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := addAddressToGrayListTest(t, stub, s)
	validationResultAddAddressToGrayListTest(t, stub, resp, s)
}

func TestGrayListEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &seriesGrayList{
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := addAddressToGrayListTest(t, stub, s)
	validationResultAddAddressToGrayListTest(t, stub, resp, s)
}

func TestGrayListWrongAddress(t *testing.T) {
	t.Parallel()

	s := &seriesGrayList{
		testAddress: common.TestWrongAddress,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := addAddressToGrayListTest(t, stub, s)
	validationResultAddAddressToGrayListTest(t, stub, resp, s)
}

func TestRemoveAddressFromGrayListTrue(t *testing.T) {
	t.Parallel()

	s := &seriesGrayList{
		testAddress: common.TestAddr,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := removeAddressFromGrayList(t, stub, s)
	validationResultRemoveAddressFromGrayList(t, stub, resp, s)
}

func TestRemoveAddressFromGrayListEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &seriesGrayList{
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := removeAddressFromGrayList(t, stub, s)
	validationResultRemoveAddressFromGrayList(t, stub, resp, s)
}

func TestRemoveAddressFromGrayListWrongAddress(t *testing.T) {
	t.Parallel()

	s := &seriesGrayList{
		testAddress: common.TestWrongAddress,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := removeAddressFromGrayList(t, stub, s)
	validationResultRemoveAddressFromGrayList(t, stub, resp, s)
}

func addAddressToGrayListTest(t *testing.T, stub *shimtest.MockStub, ser *seriesGrayList) peer.Response {
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte("true")},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	respGrayList := stub.MockInvoke("0", [][]byte{[]byte(common.FnAddToList), []byte(ser.testAddress), []byte(cc.GrayList)})

	return respGrayList
}

func validationResultAddAddressToGrayListTest(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *seriesGrayList) {
	require.Equal(t, ser.respStatus, resp.Status)
	require.Contains(t, resp.Message, ser.errorMsg)

	if resp.Status != int32(shim.OK) {
		return
	}

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	require.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.NotNil(t, response.Account)
	require.Equal(t, true, response.Account.GrayListed, "user is not gray listed")
}

func removeAddressFromGrayList(t *testing.T, stub *shimtest.MockStub, ser *seriesGrayList) peer.Response {
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte("true")},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	respGrayList := stub.MockInvoke("0", [][]byte{[]byte(common.FnAddToList), []byte(common.TestAddr), []byte(cc.GrayList)})
	require.Equal(t, int32(shim.OK), respGrayList.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	require.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.NotNil(t, response.Account)
	require.Equal(t, true, response.Account.GrayListed, "user is not gray listed")

	respDelFromList := stub.MockInvoke("0", [][]byte{[]byte(common.FnDelFromList), []byte(ser.testAddress), []byte(cc.GrayList)})

	return respDelFromList
}

func validationResultRemoveAddressFromGrayList(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *seriesGrayList) {
	require.Equal(t, ser.respStatus, resp.Status)
	require.Contains(t, resp.Message, ser.errorMsg)

	if resp.Status != int32(shim.OK) {
		return
	}

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	require.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.NotNil(t, response.Account)
	require.Equal(t, false, response.Account.GrayListed, "user is gray listed")
}
