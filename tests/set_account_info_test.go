package tests

import (
	"encoding/json"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/common"
	"strconv"
	"testing"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
)

type serieSetAccountInfo struct {
	testAddress   string
	respStatus    int32
	isGraylisted  string
	isBlacklisted string
	errorMsg      string
}

func TestSetAccountInfoTrueAddressFalseLists(t *testing.T) {
	t.Parallel()

	s := &serieSetAccountInfo{
		testAddress:   common.TestAddr,
		respStatus:    int32(shim.OK),
		isGraylisted:  "false",
		isBlacklisted: "false",
		errorMsg:      "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoTrueAddressTrueGrayListFalseBlackLists(t *testing.T) {
	t.Parallel()

	s := &serieSetAccountInfo{
		testAddress:   common.TestAddr,
		respStatus:    int32(shim.OK),
		isGraylisted:  "true",
		isBlacklisted: "false",
		errorMsg:      "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoTrueAddressFalseGrayListTrueBlackLists(t *testing.T) {
	t.Parallel()

	s := &serieSetAccountInfo{
		testAddress:   common.TestAddr,
		respStatus:    int32(shim.OK),
		isGraylisted:  "false",
		isBlacklisted: "true",
		errorMsg:      "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoTrueAddressTrueLists(t *testing.T) {
	t.Parallel()

	s := &serieSetAccountInfo{
		testAddress:   common.TestAddr,
		respStatus:    int32(shim.OK),
		isGraylisted:  "true",
		isBlacklisted: "true",
		errorMsg:      "",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &serieSetAccountInfo{
		testAddress:   "",
		respStatus:    int32(shim.ERROR),
		isGraylisted:  "false",
		isBlacklisted: "false",
		errorMsg:      errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieSetAccountInfo{
		testAddress:   "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		respStatus:    int32(shim.ERROR),
		isGraylisted:  "false",
		isBlacklisted: "false",
		errorMsg:      "account info for address 2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt is empty",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoWrongAddressString(t *testing.T) {
	t.Parallel()

	s := &serieSetAccountInfo{
		testAddress:   "AbracadabraAbracadabraAbracadabraAbracadabra",
		respStatus:    int32(shim.ERROR),
		isGraylisted:  "false",
		isBlacklisted: "false",
		errorMsg:      "invalid address, checksum error",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func TestSetAccountInfoWrongAddressNumeric(t *testing.T) {
	t.Parallel()

	s := &serieSetAccountInfo{
		testAddress:   "111111111111111111111111111111111111111",
		respStatus:    int32(shim.ERROR),
		isGraylisted:  "false",
		isBlacklisted: "false",
		errorMsg:      "invalid address, checksum error",
	}

	stub := common.StubCreateAndInit(t)
	resp := setAccountInfo(t, stub, s)
	validationResultSetAccountInfo(t, stub, resp, s)
}

func setAccountInfo(t *testing.T, stub *shimtest.MockStub, ser *serieSetAccountInfo) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	check := stub.MockInvoke(
		"0",
		[][]byte{[]byte("setAccountInfo"), []byte(ser.testAddress), []byte("kycHash2"), []byte(ser.isGraylisted), []byte(ser.isBlacklisted)},
	)

	return check
}

func validationResultSetAccountInfo(t *testing.T, stub *shimtest.MockStub, resp peer.Response, ser *serieSetAccountInfo) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	check := stub.MockInvoke("0", [][]byte{[]byte(common.FnGetAccInfoFn), []byte(ser.testAddress)})
	assert.Equal(t, ser.respStatus, check.Status)

	isGraylistedBool, err := strconv.ParseBool(ser.isGraylisted)
	assert.NoError(t, err)
	isBlacklistedBool, err := strconv.ParseBool(ser.isBlacklisted)
	assert.NoError(t, err)

	addrFromLedger := &pb.AccountInfo{}
	assert.NoError(t, json.Unmarshal(check.Payload, addrFromLedger))
	assert.Equal(t, "kycHash2", addrFromLedger.KycHash)
	assert.Equal(t, isGraylistedBool, addrFromLedger.GrayListed)
	assert.Equal(t, isBlacklistedBool, addrFromLedger.BlackListed)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	assert.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, isGraylistedBool, response.Account.GrayListed, "user is not graylisted")
	assert.Equal(t, isBlacklistedBool, response.Account.BlackListed, "user is not blacklisted")
}
