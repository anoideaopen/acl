package cc

import (
	"testing"

	pb "github.com/atomyze-foundation/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
)

type serieCheckAddress struct {
	testAddress string
	respStatus  int32
	errorMsg    string
}

// add dinamyc errorMsg in serie
func (s *serieCheckAddress) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestCheckAddressTrue(t *testing.T) {
	t.Parallel()

	s := &serieCheckAddress{
		testAddress: testaddr,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := StubCreate(t)
	resp := checkAddress(t, stub, s)
	validationResultCheckAddress(t, resp, s)
}

func TestCheckAddressEmptyAddress(t *testing.T) {
	t.Parallel()

	s := &serieCheckAddress{
		testAddress: "",
		respStatus:  int32(shim.ERROR),
		errorMsg:    ErrEmptyAddress,
	}

	stub := StubCreate(t)
	resp := checkAddress(t, stub, s)
	validationResultCheckAddress(t, resp, s)
}

func TestCheckAddressWrongAddress(t *testing.T) {
	t.Parallel()

	s := &serieCheckAddress{
		testAddress: "2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "no pub keys for address " + s.testAddress
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := checkAddress(t, stub, s)
	validationResultCheckAddress(t, resp, s)
}

func TestCheckAddressWrongAddressSymbols(t *testing.T) {
	t.Parallel()

	s := &serieCheckAddress{
		testAddress: "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		respStatus:  int32(shim.ERROR),
	}

	errorMsg := "no pub keys for address " + s.testAddress
	s.SetError(errorMsg)

	stub := StubCreate(t)
	resp := checkAddress(t, stub, s)
	validationResultCheckAddress(t, resp, s)
}

func checkAddress(t *testing.T, stub *shimtest.MockStub, ser *serieCheckAddress) peer.Response {
	// add user first
	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	check := stub.MockInvoke("0", [][]byte{[]byte("checkAddress"), []byte(ser.testAddress)})

	return check
}

func validationResultCheckAddress(t *testing.T, resp peer.Response, ser *serieCheckAddress) {
	assert.Equal(t, ser.respStatus, resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)

	if resp.Status != int32(shim.OK) {
		return
	}

	addrFromLedger := &pb.Address{}
	assert.NoError(t, proto.Unmarshal(resp.Payload, addrFromLedger))
	assert.Equal(t, ser.testAddress, base58.CheckEncode(addrFromLedger.Address[1:], addrFromLedger.Address[0]), "invalid address")
	assert.Equal(t, testUserID, addrFromLedger.UserID, "invalid userID")
	assert.Equal(t, true, addrFromLedger.IsIndustrial, "invalid isIndustrial field")
	assert.Equal(t, false, addrFromLedger.IsMultisig, "invalid IsMultisig field")
}
