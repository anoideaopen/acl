package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBlackList(t *testing.T) {
	for _, testCase := range []struct {
		description string
		fname       string
		args        func() []string
		respStatus  int32
		errorMsg    string
	}{
		{
			description: "true",
			fname:       common.FnAddToList,
			args: func() []string {
				return []string{common.TestAddr, string(cc.BlackList)}
			},
			respStatus: int32(shim.OK),
			errorMsg:   "",
		},
		{
			description: "empty address",
			fname:       common.FnAddToList,
			args: func() []string {
				return []string{"", string(cc.BlackList)}
			},
			respStatus: int32(shim.ERROR),
			errorMsg:   errs.ErrEmptyAddress,
		},
		{
			description: "wrong address",
			fname:       common.FnAddToList,
			args: func() []string {
				return []string{common.TestWrongAddress, string(cc.BlackList)}
			},
			respStatus: int32(shim.ERROR),
			errorMsg:   "account info for address " + common.TestWrongAddress + " is empty",
		},
		{
			description: "wrong parameter list",
			fname:       common.FnAddToList,
			args: func() []string {
				return []string{common.TestAddr, "kek"}
			},
			respStatus: int32(shim.ERROR),
			errorMsg:   "kek is not valid list type, accepted 'black' or 'gray' only",
		},
		{
			description: "less args",
			fname:       common.FnAddToList,
			args: func() []string {
				return []string{common.TestAddr}
			},
			respStatus: int32(shim.ERROR),
			errorMsg:   "incorrect number of arguments",
		},
		{
			description: "remove true",
			fname:       common.FnDelFromList,
			args: func() []string {
				return []string{common.TestAddr, string(cc.BlackList)}
			},
			respStatus: int32(shim.OK),
			errorMsg:   "",
		},
		{
			description: "remove empty address",
			fname:       common.FnDelFromList,
			args: func() []string {
				return []string{"", string(cc.BlackList)}
			},
			respStatus: int32(shim.ERROR),
			errorMsg:   errs.ErrEmptyAddress,
		},
		{
			description: "remove wrong address",
			fname:       common.FnDelFromList,
			args: func() []string {
				return []string{common.TestWrongAddress, string(cc.BlackList)}
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
			if testCase.fname == common.FnDelFromList {
				info.BlackListed = true
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
			mockStub.GetFunctionAndParametersReturns(testCase.fname, args)
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				require.Equal(t, mockStub.PutStateCallCount(), 0)
				return
			}

			require.Equal(t, 1, mockStub.PutStateCallCount())
			keyState, valState := mockStub.PutStateArgsForCall(0)
			require.Equal(t, key, keyState)

			addrFromLedger := &pb.AccountInfo{}
			require.NoError(t, proto.Unmarshal(valState, addrFromLedger))

			flag := true
			if testCase.fname == common.FnDelFromList {
				flag = false
			}
			require.True(t, proto.Equal(addrFromLedger, &pb.AccountInfo{
				KycHash:     "kycHash",
				BlackListed: flag,
			}))
		})
	}
}
