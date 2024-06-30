package unit

import (
	"encoding/json"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
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

	items := make([]cc.GetAccountsInfoItem, 0)
	for i := 0; i < 5; i++ {
		items = append(items, cc.GetAccountsInfoItem{
			Method: common.FnGetAccInfoFn,
			Args:   []string{s.testAddress, s.testAddress},
		})
	}
	for i := 0; i < 5; i++ {
		items = append(items, cc.GetAccountsInfoItem{
			Method: common.FnCheckKeys,
			Args:   []string{s.testPubKey},
		})
	}
	getAccountsInfoRequest := cc.GetAccountsInfoRequest{Items: items}
	bytes, err := json.Marshal(getAccountsInfoRequest)
	require.NoError(t, err)

	resp := stub.MockInvoke("0", [][]byte{
		[]byte(common.FnGetAccountsInfo),
		bytes,
	})
	require.Equal(t, int32(200), resp.Status)
	require.NotEmpty(t, resp.Payload)
	getAccountsInfoResponse := cc.GetAccountsInfoResponse{}
	err = json.Unmarshal(resp.Payload, &getAccountsInfoResponse)
	require.NoError(t, err)
	require.Equal(t, 15, len(getAccountsInfoResponse.Responses))

	for _, response := range getAccountsInfoResponse.Responses[:10] {
		expectedResponse := &seriesGetAccountInfo{
			testAddress: common.TestAddr,
			respStatus:  int32(shim.OK),
			errorMsg:    "",
		}
		validationResultGetAccountInfo(t, response, expectedResponse)
		require.Equal(t, int32(shim.OK), response.Status)
	}

	for _, response := range getAccountsInfoResponse.Responses[10:] {
		require.Equal(t, int32(shim.OK), response.Status)
		require.Empty(t, response.Message)
		aclResponse := &pb.AclResponse{}
		require.NoError(t, proto.Unmarshal(response.GetPayload(), aclResponse))
		require.Equal(t, s.testAddress, aclResponse.Address.Address.AddrString())
	}
}
