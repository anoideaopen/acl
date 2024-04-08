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

type serieGrayList struct {
	testAddress string
	respStatus  int32
	errorMsg    string
}

// add dinamyc errorMsg in serie
func (s *serieGrayList) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestGrayListTrue(t *testing.T) {
	t.Parallel()

	s := &serieGrayList{
		testAddress: testaddr,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := addAddressToGrayListTest(t, stub, s)
	validationResultAddAddressToGrayListTest(t, stub, resp, s)
}

func TestGrayListEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &serieGrayList{
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    ErrEmptyAddress,
	}

	stub := StubCreate(t)
	resp := addAddressToGrayListTest(t, stub, s)
	validationResultAddAddressToGrayListTest(t, stub, resp, s)
}

func TestGrayListWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieGrayList{
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "Account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := addAddressToGrayListTest(t, stub, s)
	validationResultAddAddressToGrayListTest(t, stub, resp, s)
}

func TestRemoveAddressFromGrayListTrue(t *testing.T) {
	t.Parallel()

	s := &serieGrayList{
		testAddress: testaddr,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := removeAddressFromGrayList(t, stub, s)
	validationResultRemoveAddressFromGrayList(t, stub, resp, s)
}

func TestRemoveAddressFromGrayListEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &serieGrayList{
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    ErrEmptyAddress,
	}

	stub := StubCreate(t)
	resp := removeAddressFromGrayList(t, stub, s)
	validationResultRemoveAddressFromGrayList(t, stub, resp, s)
}

func TestRemoveAddressFromGrayListWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieGrayList{
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "Account info for address " + s.testAddress + " is empty"
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := removeAddressFromGrayList(t, stub, s)
	validationResultRemoveAddressFromGrayList(t, stub, resp, s)
}

func addAddressToGrayListTest(t *testing.T, stub *shimtest.MockStub, ser *serieGrayList) peer.Response {
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte("true")},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	respGrayList := stub.MockInvoke("0", [][]byte{[]byte(fnAddToList), []byte(ser.testAddress), []byte(GrayList)})

	return respGrayList
}

func validationResultAddAddressToGrayListTest(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *serieGrayList) {
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
	assert.Equal(t, true, response.Account.GrayListed, "user is not gray listed")
}

func removeAddressFromGrayList(t *testing.T, stub *shimtest.MockStub, ser *serieGrayList) peer.Response {
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte("true")},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	respGrayList := stub.MockInvoke("0", [][]byte{[]byte(fnAddToList), []byte(testaddr), []byte(GrayList)})
	assert.Equal(t, int32(shim.OK), respGrayList.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(pubkey)})
	assert.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, true, response.Account.GrayListed, "user is not gray listed")

	respDelFromList := stub.MockInvoke("0", [][]byte{[]byte(fnDelFromList), []byte(ser.testAddress), []byte(GrayList)})

	return respDelFromList
}

func validationResultRemoveAddressFromGrayList(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *serieGrayList) {
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
	assert.Equal(t, false, response.Account.GrayListed, "user is gray listed")
}
