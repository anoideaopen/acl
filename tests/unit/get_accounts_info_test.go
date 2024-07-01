package unit

import (
	"encoding/json"
	"testing"

	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
)

func TestGetAccountsInfo(t *testing.T) {
	t.Parallel()

	s := &seriesAddUser{
		testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		testAddress: "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N",
		kycHash:     kycHash,
		testUserID:  testUserID,
		respStatus:  int32(shim.OK),
		errorMsg:    "",
	}

	stub := common.StubCreateAndInit(t)
	respAddUser := addUser(stub, s)
	validationResultAddUser(t, stub, respAddUser, s)

	args := make([][]byte, 0)
	args = append(args, []byte(common.FnGetAccountsInfo))
	for i := 0; i < 5; i++ {
		bytes, err := json.Marshal([]string{common.FnGetAccInfoFn, s.testAddress})
		require.NoError(t, err)
		args = append(args, bytes)
	}
	for i := 0; i < 5; i++ {
		bytes, err := json.Marshal([]string{common.FnCheckKeys, s.testPubKey})
		require.NoError(t, err)
		args = append(args, bytes)
	}

	resp := stub.MockInvoke("0", args)
	require.Equal(t, int32(200), resp.Status)
	require.NotEmpty(t, resp.Payload)
	var responses []peer.Response
	err := json.Unmarshal(resp.Payload, &responses)
	require.NoError(t, err)
	require.Equal(t, 10, len(responses))

	for _, response := range responses[:5] {
		expectedResponse := &seriesGetAccountInfo{
			testAddress: common.TestAddr,
			respStatus:  int32(shim.OK),
			errorMsg:    "",
		}
		validationResultGetAccountInfo(t, response, expectedResponse)
		require.Equal(t, int32(shim.OK), response.Status)
	}

	for _, response := range responses[5:] {
		require.Equal(t, int32(shim.OK), response.Status)
		require.Empty(t, response.Message)
		aclResponse := &pb.AclResponse{}
		require.NoError(t, proto.Unmarshal(response.GetPayload(), aclResponse))
		require.Equal(t, s.testAddress, aclResponse.Address.Address.AddrString())
	}
}
