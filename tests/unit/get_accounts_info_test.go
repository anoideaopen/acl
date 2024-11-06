package unit

import (
	"encoding/json"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestGetAccountsInfo(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description string
		args        func() []string
		checkResp   func([]peer.Response)
		errorMsg    string
	}{
		{
			description: "empty",
			args: func() []string {
				return nil
			},
			checkResp: func(responses []peer.Response) {
				require.Empty(t, responses)
			},
			errorMsg: "",
		},
		{
			description: "not enough arguments",
			args: func() []string {
				bytes, err := json.Marshal([]string{"test"})
				require.NoError(t, err)
				return []string{string(bytes)}
			},
			checkResp: func(responses []peer.Response) {
				require.Len(t, responses, 1)
				require.Equal(t, int32(500), responses[0].GetStatus())
				require.Equal(t, "not enough arguments '[\"test\"]'", responses[0].GetMessage())
			},
			errorMsg: "",
		},
		{
			description: "wrong method name",
			args: func() []string {
				bytes, err := json.Marshal([]string{"tesst", "21"})
				require.NoError(t, err)
				return []string{string(bytes)}
			},
			checkResp: func(responses []peer.Response) {
				require.Len(t, responses, 1)
				require.Equal(t, int32(500), responses[0].GetStatus())
				require.Contains(t, responses[0].GetMessage(), "failed get accounts info: unknown method tesst")
			},
			errorMsg: "",
		},
		{
			description: "ok and err resp",
			args: func() []string {
				bytes0, err := json.Marshal([]string{"tesst", "21"})
				require.NoError(t, err)
				bytes1, err := json.Marshal([]string{common.FnGetAccInfoFn, "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N"})
				require.NoError(t, err)
				return []string{string(bytes0), string(bytes1)}
			},
			checkResp: func(responses []peer.Response) {
				require.Len(t, responses, 2)

				require.Equal(t, int32(500), responses[0].GetStatus())
				require.Contains(t, responses[0].GetMessage(), "failed get accounts info: unknown method tesst")

				require.Equal(t, int32(shim.OK), responses[1].GetStatus())
				require.Empty(t, responses[1].Message)
				addrFromLedger := &pb.AccountInfo{}
				require.NoError(t, json.Unmarshal(responses[1].Payload, addrFromLedger))
				require.True(t, proto.Equal(addrFromLedger, &pb.AccountInfo{KycHash: kycHash}))
			},
			errorMsg: "",
		},
		{
			description: "ok",
			args: func() []string {
				args := make([]string, 0, 10)
				for i := 0; i < 5; i++ {
					bytes, err := json.Marshal([]string{common.FnGetAccInfoFn, "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N"})
					require.NoError(t, err)
					args = append(args, string(bytes))
				}
				for i := 0; i < 5; i++ {
					bytes, err := json.Marshal([]string{common.FnCheckKeys, "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z"})
					require.NoError(t, err)
					args = append(args, string(bytes))
				}
				return args
			},
			checkResp: func(responses []peer.Response) {
				require.Equal(t, 10, len(responses))

				for _, response := range responses[:5] {
					require.Equal(t, int32(shim.OK), response.GetStatus())
					require.Empty(t, response.Message)
					addrFromLedger := &pb.AccountInfo{}
					require.NoError(t, json.Unmarshal(response.Payload, addrFromLedger))
					require.True(t, proto.Equal(addrFromLedger, &pb.AccountInfo{KycHash: kycHash}))
				}

				for _, response := range responses[5:] {
					require.Equal(t, int32(shim.OK), response.GetStatus())
					require.Empty(t, response.Message)

					aclResponse := &pb.AclResponse{}
					require.NoError(t, proto.Unmarshal(response.GetPayload(), aclResponse))
					require.Equal(t, "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N", aclResponse.Address.Address.AddrString())
				}
			},
			errorMsg: "",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			key, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{"FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N"})
			require.NoError(t, err)
			info := &pb.AccountInfo{
				KycHash: kycHash,
			}
			key1, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{"2132448f85aac86548adbec3f439233bda4e556991b0dd35698520c82cf829dd"})
			require.NoError(t, err)
			bytes, err := helpers.DecodeBase58PublicKey("Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z")
			require.NoError(t, err)
			hashed := sha3.Sum256(bytes)
			signAddr := &pb.SignedAddress{
				Address: &pb.Address{
					UserID:       "testUserID",
					Address:      hashed[:],
					IsIndustrial: true,
				},
			}

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				switch s {
				case "__config":
					return cfgBytes, nil
				case key:
					return proto.Marshal(info)
				case key1:
					return proto.Marshal(signAddr)
				}

				return nil, nil
			})

			ccAcl := cc.New()

			args := testCase.args()
			mockStub.GetFunctionAndParametersReturns(common.FnGetAccountsInfo, args)
			bArgs := [][]byte{[]byte(common.FnGetAccountsInfo)}
			for _, arg := range args {
				bArgs = append(bArgs, []byte(arg))
			}
			mockStub.GetArgsReturns(bArgs)
			resp := ccAcl.Invoke(mockStub)

			// check result
			require.Equal(t, int32(shim.OK), resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)
			require.NotEmpty(t, resp.Payload)
			var responses []peer.Response
			err = json.Unmarshal(resp.Payload, &responses)
			require.NoError(t, err)
			testCase.checkResp(responses)
		})
	}
}
