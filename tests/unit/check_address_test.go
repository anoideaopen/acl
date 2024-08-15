package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
)

type seriesCheckAddress struct {
	testAddress string
	respStatus  int32
	errorMsg    string
}

// add dynamic errorMsg in series
func (s *seriesCheckAddress) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestCheckAddressTrue(t *testing.T) {
	t.Parallel()

	s := &seriesCheckAddress{
		testAddress: common.TestAddr,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	resp := checkAddress(t, stub, s)
	validationResultCheckAddress(t, resp, s)
}

func TestCheckAddressEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &seriesCheckAddress{
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    errs.ErrEmptyAddress,
	}

	stub := common.StubCreateAndInit(t)
	resp := checkAddress(t, stub, s)
	validationResultCheckAddress(t, resp, s)
}

func TestCheckAddressWrongAddress(t *testing.T) {
	t.Parallel()

	s := &seriesCheckAddress{
		testAddress: common.TestWrongAddress,
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "no public keys for address " + s.testAddress
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := checkAddress(t, stub, s)
	validationResultCheckAddress(t, resp, s)
}

func TestCheckAddressWrongAddressSymbols(t *testing.T) {
	t.Parallel()

	s := &seriesCheckAddress{
		testAddress: "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "no public keys for address " + s.testAddress
	s.SetError(errorMsg)

	stub := common.StubCreateAndInit(t)
	resp := checkAddress(t, stub, s)
	validationResultCheckAddress(t, resp, s)
}

func checkAddress(t *testing.T, stub *shimtest.MockStub, ser *seriesCheckAddress) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	check := stub.MockInvoke("0", [][]byte{[]byte("checkAddress"), []byte(ser.testAddress)})

	return check
}

func validationResultCheckAddress(t *testing.T, resp peer.Response, ser *seriesCheckAddress) {
	require.Equal(t, ser.respStatus, resp.Status)
	require.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	addrFromLedger := &pb.Address{}
	require.NoError(t, proto.Unmarshal(resp.Payload, addrFromLedger))
	require.Equal(t, ser.testAddress, base58.CheckEncode(addrFromLedger.Address[1:], addrFromLedger.Address[0]), "invalid address")
	require.Equal(t, testUserID, addrFromLedger.UserID, "invalid userID")
	require.Equal(t, true, addrFromLedger.IsIndustrial, "invalid isIndustrial field")
	require.Equal(t, false, addrFromLedger.IsMultisig, "invalid IsMultisig field")
}
