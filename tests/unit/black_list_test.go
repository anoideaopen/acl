package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/stretchr/testify/require"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
)

type seriesBlackList struct {
	testAddress string
	list        string
	respStatus  int32
	errorMsg    string
}

// add dynamic errorMsg in series
func (s *seriesBlackList) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestBlackListTrue(t *testing.T) {
	t.Parallel()

	s := &seriesBlackList{
		testAddress: common.TestAddr,
		list:        "black",
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := addAddressToBlackList(t, stub, s)
	validationResultAddAddressToBlackList(t, stub, resp, s)
}

func TestBlackListEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &seriesBlackList{
		testAddress: "",
		list:        "black",
		respStatus:  int32(shim.ERROR),
		errorMsg:    errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := addAddressToBlackList(t, stub, s)
	validationResultAddAddressToBlackList(t, stub, resp, s)
}

func TestBlackListWrongAddress(t *testing.T) {
	t.Parallel()

	s := &seriesBlackList{
		testAddress: common.TestWrongAddress,
		list:        "black",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := addAddressToBlackList(t, stub, s)
	validationResultAddAddressToBlackList(t, stub, resp, s)
}

func TestBlackListWrongParameterList(t *testing.T) {
	t.Parallel()

	s := &seriesBlackList{
		testAddress: common.TestAddr,
		list:        "kek",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := s.list + " is not valid list type, accepted 'black' or 'gray' only"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := addAddressToBlackList(t, stub, s)
	validationResultAddAddressToBlackList(t, stub, resp, s)
}

func TestBlackListLessArgs(t *testing.T) {
	t.Parallel()

	stub := common.StubCreateAndInit(t)
	resp := stub.MockInvoke("0", [][]byte{
		[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue),
	})
	require.Equal(t, int32(shim.OK), resp.Status, resp.Message)

	respBlackList := stub.MockInvoke("0", [][]byte{[]byte(common.FnAddToList), []byte(common.TestAddr)})
	require.Equal(t, int32(shim.ERROR), respBlackList.Status)
	require.Contains(t, respBlackList.Message, "incorrect number of arguments")
}

func TestRemoveAddressFromBlackListTrue(t *testing.T) {
	t.Parallel()

	s := &seriesBlackList{
		testAddress: common.TestAddr,
		list:        "black",
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := removeAddressFromBlackList(t, stub, s)
	validationResultRemoveAddressFromBlackList(t, stub, resp, s)
}

func TestRemoveAddressFromBlackListEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &seriesBlackList{
		testAddress: "",
		list:        "black",
		respStatus:  int32(shim.ERROR),
		errorMsg:    errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := removeAddressFromBlackList(t, stub, s)
	validationResultRemoveAddressFromBlackList(t, stub, resp, s)
}

func TestRemoveAddressFromBlackListWrongAddress(t *testing.T) {
	t.Parallel()

	s := &seriesBlackList{
		testAddress: common.TestWrongAddress,
		list:        "black",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := removeAddressFromBlackList(t, stub, s)
	validationResultRemoveAddressFromBlackList(t, stub, resp, s)
}

func addAddressToBlackList(t *testing.T, stub *shimtest.MockStub, ser *seriesBlackList) peer.Response {
	resp := stub.MockInvoke("0", [][]byte{
		[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue),
	})
	require.Equal(t, int32(shim.OK), resp.Status, resp.Message)

	respBlackList := stub.MockInvoke("0", [][]byte{[]byte(common.FnAddToList), []byte(ser.testAddress), []byte(ser.list)})

	return respBlackList
}

func validationResultAddAddressToBlackList(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *seriesBlackList) {
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
	require.Equal(t, true, response.Account.BlackListed, "user is not blacklisted")
}

func removeAddressFromBlackList(t *testing.T, stub *shimtest.MockStub, ser *seriesBlackList) peer.Response {
	resp := stub.MockInvoke("0", [][]byte{
		[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte("true"),
	})
	require.Equal(t, int32(shim.OK), resp.Status, resp.Message)

	respBlackList := stub.MockInvoke("0", [][]byte{[]byte(common.FnAddToList), []byte(common.TestAddr), []byte(ser.list)})
	require.Equal(t, int32(shim.OK), respBlackList.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	require.Equal(t, int32(shim.OK), result.Status)
	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.NotNil(t, response.Account)
	require.Equal(t, true, response.Account.BlackListed, "user is not blacklisted")

	respDelFromList := stub.MockInvoke("0", [][]byte{[]byte(common.FnDelFromList), []byte(ser.testAddress), []byte("black")})

	return respDelFromList
}

func validationResultRemoveAddressFromBlackList(
	t *testing.T,
	stub *shimtest.MockStub,
	resp peer.Response,
	ser *seriesBlackList,
) {
	require.Equal(t, ser.respStatus, resp.Status)
	require.Contains(t, resp.Message, ser.errorMsg)

	if resp.Status != int32(shim.OK) {
		return
	}

	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	require.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.NotNil(t, response.Account)
	require.Equal(t, false, response.Account.BlackListed, "user is blacklisted")
}
