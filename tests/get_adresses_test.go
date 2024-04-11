package tests

import (
	"testing"

	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/assert"
)

func TestGetAddresses(t *testing.T) {
	stub := common.StubCreateAndInit(t)

	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte("true")},
	)
	assert.Equal(t, int32(shim.OK), resp.Status)

	respGetAddr := stub.MockInvoke("0", [][]byte{[]byte("getAddresses"), []byte("1"), []byte(common.TestAddr)})
	// assert.Equal(t, int32(shim.OK), respGetAddr.Status)
	assert.Equal(t, int32(0), respGetAddr.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	assert.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	assert.NoError(t, proto.Unmarshal(result.Payload, response))
	assert.NotNil(t, response.Address)
	assert.NotNil(t, response.Account)
	assert.Equal(t, common.TestAddr, response.Address.Address.AddrString(), "invalid address")
	assert.Equal(t, kycHash, response.Account.KycHash)
	assert.False(t, response.Account.GrayListed)
	assert.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
	assert.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
	assert.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
}
