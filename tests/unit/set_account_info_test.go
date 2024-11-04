package unit

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
)

func TestSetAccountInfo(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description   string
		testAddress   string
		respStatus    int32
		isGrayListed  bool
		isBlackListed bool
		errorMsg      string
	}{
		{
			description:   "true address false lists",
			testAddress:   common.TestAddr,
			respStatus:    int32(shim.OK),
			isGrayListed:  false,
			isBlackListed: false,
			errorMsg:      "",
		},
		{
			description:   "true address true gray list false black lists",
			testAddress:   common.TestAddr,
			respStatus:    int32(shim.OK),
			isGrayListed:  true,
			isBlackListed: false,
			errorMsg:      "",
		},
		{
			description:   "true address false gray list true black lists",
			testAddress:   common.TestAddr,
			respStatus:    int32(shim.OK),
			isGrayListed:  false,
			isBlackListed: true,
			errorMsg:      "",
		},
		{
			description:   "true address true lists",
			testAddress:   common.TestAddr,
			respStatus:    int32(shim.OK),
			isGrayListed:  true,
			isBlackListed: true,
			errorMsg:      "",
		},
		{
			description:   "empty address",
			testAddress:   "",
			respStatus:    int32(shim.ERROR),
			isGrayListed:  false,
			isBlackListed: false,
			errorMsg:      errs.ErrEmptyAddress,
		},
		{
			description:   "info wrong address",
			testAddress:   common.TestWrongAddress,
			respStatus:    int32(shim.ERROR),
			isGrayListed:  false,
			isBlackListed: false,
			errorMsg:      fmt.Sprintf(errs.ErrAccountForAddressIsEmpty, common.TestWrongAddress),
		},
		{
			description:   "wrong address string",
			testAddress:   "AbracadabraAbracadabraAbracadabraAbracadabra",
			respStatus:    int32(shim.ERROR),
			isGrayListed:  false,
			isBlackListed: false,
			errorMsg:      "invalid address: checksum error",
		},
		{
			description:   "wrong address numeric",
			testAddress:   "111111111111111111111111111111111111111",
			respStatus:    int32(shim.ERROR),
			isGrayListed:  false,
			isBlackListed: false,
			errorMsg:      "invalid address: checksum error",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NuwMockStub(t)

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
			mockStub.GetFunctionAndParametersReturns(
				"setAccountInfo",
				[]string{testCase.testAddress, "kycHash2", strconv.FormatBool(testCase.isGrayListed), strconv.FormatBool(testCase.isBlackListed)},
			)
			resp := ccAcl.Invoke(mockStub)

			// check result
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
			require.True(t, proto.Equal(addrFromLedger, &pb.AccountInfo{
				KycHash:     "kycHash2",
				GrayListed:  testCase.isGrayListed,
				BlackListed: testCase.isBlackListed,
			}))
		})
	}
}
