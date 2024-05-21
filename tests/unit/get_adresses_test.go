package unit

import (
	"testing"

	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
)

func TestGetAddresses(t *testing.T) {
	stub := common.StubCreateAndInit(t)

	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte("true")},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	respGetAddr := stub.MockInvoke("0", [][]byte{[]byte("getAddresses"), []byte("1"), []byte(common.TestAddr)})
	// require.Equal(t, int32(shim.OK), respGetAddr.Status)
	require.Equal(t, int32(0), respGetAddr.Status)

	// check
	result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(common.PubKey)})
	require.Equal(t, int32(shim.OK), result.Status)

	response := &pb.AclResponse{}
	require.NoError(t, proto.Unmarshal(result.Payload, response))
	require.NotNil(t, response.Address)
	require.NotNil(t, response.Account)
	require.Equal(t, common.TestAddr, response.Address.Address.AddrString(), "invalid address")
	require.Equal(t, kycHash, response.Account.KycHash)
	require.False(t, response.Account.GrayListed)
	require.Equal(t, testUserID, response.Address.Address.UserID, "invalid userID")
	require.Equal(t, true, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
	require.Equal(t, false, response.Address.Address.IsMultisig, "invalid IsMultisig field")
}
