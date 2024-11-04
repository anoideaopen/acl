package unit

import (
	"encoding/json"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/anoideaopen/acl/tests/unit/mock"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
)

func TestGetAddresses(t *testing.T) {
	mockStub, cfgBytes := common.NuwMockStub(t)

	mockStub.GetStateCalls(func(s string) ([]byte, error) {
		switch s {
		case "__config":
			return cfgBytes, nil
		}

		return nil, nil
	})

	ccAcl := cc.New()
	mockStub.GetFunctionAndParametersReturns("getAddresses", []string{"1", common.TestAddr})
	resp := ccAcl.Invoke(mockStub)

	require.Equal(t, int32(shim.ERROR), resp.Status)
	require.Contains(t, resp.Message, "empty address iterator")

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
	require.Equal(t, int32(shim.OK), resp.Status)
	require.Empty(t, resp.Message)

	addr := &cc.AddrsWithPagination{}
	require.NoError(t, json.Unmarshal(resp.GetPayload(), addr))
	require.Equal(t, &cc.AddrsWithPagination{
		Addrs:    []string{common.TestAddr},
		Bookmark: "",
	}, addr)
}
