package unit

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
)

type seriesSetAccountInfo struct {
	testAddress   string
	respStatus    int32
	isGrayListed  string
	isBlackListed string
	errorMsg      string
}

func TestSetAccountInfoTrueAddressFalseLists(t *testing.T) {
	t.Parallel()

	s := &seriesSetAccountInfo{
		testAddress:   common.TestAddr,
		respStatus:    int32(shim.OK),
		isGrayListed:  "false",
		isBlackListed: "false",
		errorMsg:      "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoTrueAddressTrueGrayListFalseBlackLists(t *testing.T) {
	t.Parallel()

	s := &seriesSetAccountInfo{
		testAddress:   common.TestAddr,
		respStatus:    int32(shim.OK),
		isGrayListed:  "true",
		isBlackListed: "false",
		errorMsg:      "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoTrueAddressFalseGrayListTrueBlackLists(t *testing.T) {
	t.Parallel()

	s := &seriesSetAccountInfo{
		testAddress:   common.TestAddr,
		respStatus:    int32(shim.OK),
		isGrayListed:  "false",
		isBlackListed: "true",
		errorMsg:      "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoTrueAddressTrueLists(t *testing.T) {
	t.Parallel()

	s := &seriesSetAccountInfo{
		testAddress:   common.TestAddr,
		respStatus:    int32(shim.OK),
		isGrayListed:  "true",
		isBlackListed: "true",
		errorMsg:      "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &seriesSetAccountInfo{
		testAddress:   "",
		respStatus:    int32(shim.ERROR),
		isGrayListed:  "false",
		isBlackListed: "false",
		errorMsg:      errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoWrongAddress(t *testing.T) {
	t.Parallel()

	s := &seriesSetAccountInfo{
		testAddress:   common.TestWrongAddress,
		respStatus:    int32(shim.ERROR),
		isGrayListed:  "false",
		isBlackListed: "false",
		errorMsg:      fmt.Sprintf(errs.ErrAccountForAddressIsEmpty, common.TestWrongAddress),
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoWrongAddressString(t *testing.T) {
	t.Parallel()

	s := &seriesSetAccountInfo{
		testAddress:   "AbracadabraAbracadabraAbracadabraAbracadabra",
		respStatus:    int32(shim.ERROR),
		isGrayListed:  "false",
		isBlackListed: "false",
		errorMsg:      "invalid address, checksum error",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoWrongAddressNumeric(t *testing.T) {
	t.Parallel()

	s := &seriesSetAccountInfo{
		testAddress:   "111111111111111111111111111111111111111",
		respStatus:    int32(shim.ERROR),
		isGrayListed:  "false",
		isBlackListed: "false",
		errorMsg:      "invalid address, checksum error",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func setAccountInfo(t *testing.T, stub *shimtest.MockStub, ser *seriesSetAccountInfo) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	check := stub.MockInvoke(
		"0",
		[][]byte{[]byte("setAccountInfo"), []byte(ser.testAddress), []byte("kycHash2"), []byte(ser.isGrayListed), []byte(ser.isBlackListed)},
	)

	return check
}

func validationResultSetAccountInfo(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *seriesSetAccountInfo) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	check := stub.MockInvoke("0", [][]byte{[]byte(common.FnGetAccInfoFn), []byte(ser.testAddress)})
	assert.Equal(t, ser.respStatus, check.Status)

	isGrayListedBool, err := strconv.ParseBool(ser.isGrayListed)
	assert.NoError(t, err)
	isBlackListedBool, err := strconv.ParseBool(ser.isBlackListed)
	assert.NoError(t, err)

	addrFromLedger := &pb.AccountInfo{}
	assert.NoError(t, json.Unmarshal(check.Payload, addrFromLedger))
	assert.Equal(t, "kycHash2", addrFromLedger.KycHash)
	assert.Equal(t, isGrayListedBool, addrFromLedger.GrayListed)
	assert.Equal(t, isBlackListedBool, addrFromLedger.BlackListed)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	assert.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, isGrayListedBool, response.Account.GrayListed, "user is not grayListed")
	assert.Equal(t, isBlackListedBool, response.Account.BlackListed, "user is not blackListed")
}
