package unit

import (
	"encoding/json"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
)

func TestGetAccountInfo(t *testing.T) {
	for _, testCase := range []struct {
		description string
		args        func() []string
		respStatus  int32
		errorMsg    string
	}{
		{
			description: "true",
			args: func() []string {
				return []string{common.TestAddr}
			},
			respStatus: int32(shim.OK),
			errorMsg:   "",
		},
		{
			description: "empty address",
			args: func() []string {
				return []string{""}
			},
			respStatus: int32(shim.ERROR),
			errorMsg:   errs.ErrEmptyAddress,
		},
		{
			description: "wrong address",
			args: func() []string {
				return []string{common.TestWrongAddress}
			},
			respStatus: int32(shim.ERROR),
			errorMsg:   "account info for address " + common.TestWrongAddress + " is empty",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			key, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{common.TestAddr})
			require.NoError(t, err)
			info := &pb.AccountInfo{
				KycHash: kycHash,
			}
			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				switch s {
				case "__config":
					return cfgBytes, nil
				case key:
					return proto.Marshal(info)
				}

				return nil, nil
			})

			ccAcl := cc.New()
			args := testCase.args()
			mockStub.GetFunctionAndParametersReturns(common.FnGetAccInfoFn, args)
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				return
			}

			addrFromLedger := &pb.AccountInfo{}
			require.NoError(t, json.Unmarshal(resp.GetPayload(), addrFromLedger))

			require.Equal(t, addrFromLedger, &pb.AccountInfo{
				KycHash: "kycHash",
			})
		})
	}
}
