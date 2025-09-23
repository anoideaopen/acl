package unit

import (
	"errors"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/stretchr/testify/require"
)

func TestACLOptions(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		description string
		fn          string
		args        []string
		respStatus  int32
		errorMsg    string
		options     []cc.Option
	}{
		{
			description: "Run ACL without options",
			fn:          common.FnAddUser,
			args:        []string{common.TestUsers[0].PublicKey, kycHash, testUserID, stateTrue},
			respStatus:  int32(shim.OK),
			options:     nil,
		},
		{
			description: "Run ACL with options that tries to replace functions that already exist",
			fn:          common.FnAddUser,
			args:        []string{common.TestUsers[0].PublicKey, kycHash, testUserID, stateTrue},
			respStatus:  int32(shim.OK),
			options: []cc.Option{cc.WithAdditionalMethods(map[string]any{
				common.FnAddUser: func(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
					return nil, errors.New("FnAddUser returns error")
				},
			})},
		},
		{
			description: "Run ACL with options that tries to add new function",
			fn:          "myNewFunction",
			args:        []string{"arg1", "arg2"},
			respStatus:  int32(shim.OK),
			options: []cc.Option{cc.WithAdditionalMethods(map[string]any{
				"myNewFunction": func(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
					return []byte("OK"), nil
				},
			})},
		},
		{
			description: "Run ACL with options that tries to add new function which always returns error",
			fn:          "myNewFunctionReturnErr",
			args:        []string{"arg1", "arg2"},
			respStatus:  int32(shim.ERROR),
			errorMsg:    "error occurred",
			options: []cc.Option{cc.WithAdditionalMethods(map[string]any{
				"myNewFunctionReturnErr": func(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
					return nil, errors.New("error occurred")
				},
			})},
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)
			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				switch s {
				case "__config":
					return cfgBytes, nil
				}

				return nil, nil
			})
			ccAcl := cc.New(testCase.options...)
			mockStub.GetFunctionAndParametersReturns(testCase.fn, testCase.args)
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				return
			}
		})
	}
}
