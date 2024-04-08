package cc

import (
	"testing"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
)

type serieBlackList struct {
	testAddress string
	list        string
	respStatus  int32
	errorMsg    string
}

// add dinamyc errorMsg in serie
func (s *serieBlackList) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestBlackListTrue(t *testing.T) {
	t.Parallel()

	s := &serieBlackList{
		testAddress: testaddr,
		list:        "black",
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := addAddressToBlackList(t, stub, s)
	validationResultAddAddressToBlackList(t, stub, resp, s)
}

func TestBlackListEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &serieBlackList{
		testAddress: "",
		list:        "black",
		respStatus:  int32(shim.ERROR),
		errorMsg:    ErrEmptyAddress,
	}

	stub := StubCreate(t)
	resp := addAddressToBlackList(t, stub, s)
	validationResultAddAddressToBlackList(t, stub, resp, s)
}

func TestBlackListWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieBlackList{
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		list:        "black",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "Account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := addAddressToBlackList(t, stub, s)
	validationResultAddAddressToBlackList(t, stub, resp, s)
}

func TestBlackListWrongParameterList(t *testing.T) {
	t.Parallel()

	s := &serieBlackList{
		testAddress: testaddr,
		list:        "kek",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "%s is not valid list type, accepted 'black' or 'gray' only"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := addAddressToBlackList(t, stub, s)
	validationResultAddAddressToBlackList(t, stub, resp, s)
}

func TestBlackListLessArgs(t *testing.T) {
	t.Parallel()

	stub := StubCreate(t)
	resp := stub.MockInvoke("0", [][]byte{
		[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue),
	})
	assert.Equal(t, int32(shim.OK), resp.Status, resp.Message)

	respBlackList := stub.MockInvoke("0", [][]byte{[]byte(fnAddToList), []byte(testaddr)})
	assert.Equal(t, int32(shim.ERROR), respBlackList.Status)
	assert.Contains(t, respBlackList.Message, "incorrect number of arguments")
}

func TestRemoveAddressFromBlackListTrue(t *testing.T) {
	t.Parallel()

	s := &serieBlackList{
		testAddress: testaddr,
		list:        "black",
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := removeAddressFromBlackList(t, stub, s)
	validationResultRemoveAddressFromBlackList(t, stub, resp, s)
}

func TestRemoveAddressFromBlackListEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &serieBlackList{
		testAddress: "",
		list:        "black",
		respStatus:  int32(shim.ERROR),
		errorMsg:    ErrEmptyAddress,
	}

	stub := StubCreate(t)
	resp := removeAddressFromBlackList(t, stub, s)
	validationResultRemoveAddressFromBlackList(t, stub, resp, s)
}

func TestRemoveAddressFromBlackListWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieBlackList{
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		list:        "black",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "Account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := removeAddressFromBlackList(t, stub, s)
	validationResultRemoveAddressFromBlackList(t, stub, resp, s)
}

func addAddressToBlackList(t *testing.T, stub *shimtest.MockStub, ser *serieBlackList) peer.Response {
	resp := stub.MockInvoke("0", [][]byte{
		[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue),
	})
	assert.Equal(t, int32(shim.OK), resp.Status, resp.Message)

	respBlackList := stub.MockInvoke("0", [][]byte{[]byte(fnAddToList), []byte(ser.testAddress), []byte(ser.list)})

	return respBlackList
}

func validationResultAddAddressToBlackList(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *serieBlackList) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(pubkey)})
	assert.Equal(t, int32(shim.OK), result.Status)
	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, true, response.Account.BlackListed, "user is not blacklisted")
}

func removeAddressFromBlackList(t *testing.T, stub *shimtest.MockStub, ser *serieBlackList) peer.Response {
	resp := stub.MockInvoke("0", [][]byte{
		[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte("true"),
	})
	assert.Equal(t, int32(shim.OK), resp.Status, resp.Message)

	respBlackList := stub.MockInvoke("0", [][]byte{[]byte(fnAddToList), []byte(testaddr), []byte(ser.list)})
	assert.Equal(t, int32(shim.OK), respBlackList.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(pubkey)})
	assert.Equal(t, int32(shim.OK), result.Status)
	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, true, response.Account.BlackListed, "user is not blacklisted")

	respDelFromList := stub.MockInvoke("0", [][]byte{[]byte(fnDelFromList), []byte(ser.testAddress), []byte("black")})

	return respDelFromList
}

func validationResultRemoveAddressFromBlackList(
	t *testing.T,
	stub *shimtest.MockStub,
	resp peer.Response,
	ser *serieBlackList,
) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(pubkey)})
	assert.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, false, response.Account.BlackListed, "user is blacklisted")
}
