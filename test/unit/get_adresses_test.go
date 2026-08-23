package unit

import (
	"encoding/json"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/test/unit/common"
	"github.com/anoideaopen/acl/test/unit/mock"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/queryresult"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/stretchr/testify/require"
)

func TestGetAddresses(t *testing.T) {
	mockStub, cfgBytes := common.NewMockStub(t)

	mockStub.GetStateCalls(func(s string) ([]byte, error) {
		if s == "__config" {
			return cfgBytes, nil
		}

		return nil, nil
	})

	ccAcl := cc.New()
	mockStub.GetFunctionAndParametersReturns("getAddresses", []string{"1", common.TestAddr})
	resp := ccAcl.Invoke(mockStub)

	require.Equal(t, int32(shim.ERROR), resp.GetStatus())
	require.Contains(t, resp.GetMessage(), "empty address iterator")

	key, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{common.TestAddr})
	require.NoError(t, err)
	fakeIterator := &mock.StateIterator{}
	fakeIterator.HasNextReturnsOnCall(0, true)
	fakeIterator.HasNextReturnsOnCall(1, false)
	fakeIterator.NextReturns(&queryresult.KV{
		Key:   key,
		Value: []byte(common.TestAddrHashInHex),
	}, nil)
	mockStub.GetStateByPartialCompositeKeyWithPaginationReturns(fakeIterator, &peer.QueryResponseMetadata{
		FetchedRecordsCount: 1,
		Bookmark:            "",
	}, nil)

	mockStub.GetFunctionAndParametersReturns("getAddresses", []string{"1", ""})
	resp = ccAcl.Invoke(mockStub)
	require.Equal(t, int32(shim.OK), resp.GetStatus())
	require.Empty(t, resp.GetMessage())

	addr := &cc.AddrsWithPagination{}
	require.NoError(t, json.Unmarshal(resp.GetPayload(), addr))
	require.Equal(t, &cc.AddrsWithPagination{
		Addrs:    []string{common.TestAddr},
		Bookmark: "",
	}, addr)
}
