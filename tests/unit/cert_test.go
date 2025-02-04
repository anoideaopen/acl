package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/stretchr/testify/require"
)

func TestCert(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description string
		respStatus  int32
		errorMsg    string
		cert        string
	}{
		{
			description: "use no cert",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "no bytes in serialized identity",
			cert:        "",
		},
		{
			description: "use invalid cert",
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrCallerNotAdmin,
			cert:        common.UserCert,
		},
		{
			description: "use valid cert",
			respStatus:  int32(shim.OK),
			errorMsg:    "",
			cert:        common.AdminCert,
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			if len(testCase.cert) != 0 {
				common.SetCert(t, mockStub, testCase.cert)
			} else {
				mockStub.GetCreatorReturns([]byte{}, nil)
			}

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				switch s {
				case "__config":
					return cfgBytes, nil
				}

				return nil, nil
			})

			ccAcl := cc.New()
			mockStub.GetFunctionAndParametersReturns(common.FnAddUser, []string{common.PubKey, kycHash, testUserID, stateTrue})
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				require.Equal(t, mockStub.PutStateCallCount(), 0)
				return
			}

			require.Equal(t, 4, mockStub.PutStateCallCount())
		})
	}
}
