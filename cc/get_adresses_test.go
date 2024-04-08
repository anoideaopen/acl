package cc

import (
	"testing"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/stretchr/testify/assert"
)

func TestGetAdresses(t *testing.T) {
	stub := shimtest.NewMockStub("mockStub", New())
	assert.NotNil(t, stub)
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	err = SetCreator(stub, testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	stub.MockInit("0", testInitArgs)

	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte("true")},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	respGetAddr := stub.MockInvoke("0", [][]byte{[]byte("getAddresses"), []byte("1"), []byte(testaddr)})
	// assert.Equal(t, int32(shim.OK), respGetAddr.Status)
	assert.Equal(t, int32(0), respGetAddr.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(pubkey)})
	assert.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, testaddr, response.Address.Address.AddrString(), "invalid address")
	assert.Equal(t, kycHash, response.Account.KycHash)
	assert.False(t, response.Account.GrayListed)
	assert.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
	assert.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
	assert.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
}
