package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

func TestCheckAddress(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description string
		testAddress string
		respStatus  int32
		errorMsg    string
	}{
		{
			description: "true",
			testAddress: common.TestAddr,
			respStatus:  int32(shim.OK),
			errorMsg:    "",
		},
		{
			description: "empty address",
			testAddress: "",
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrEmptyAddress,
		},
		{
			description: "wrong address",
			testAddress: common.TestWrongAddress,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "no public keys for address " + common.TestWrongAddress,
		},
		{
			description: "wrong address symbols",
			testAddress: "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "no public keys for address Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			keyPk, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{common.TestAddr})
			require.NoError(t, err)
			keyAccountInfo, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{common.TestAddr})
			require.NoError(t, err)
			keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{common.TestAddrHashInHex})
			require.NoError(t, err)

			info := &pb.AccountInfo{
				KycHash: kycHash,
			}

			b, err := helpers.DecodeBase58PublicKey(common.PubKey)
			require.NoError(t, err)
			hashed := sha3.Sum256(b)
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
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(info)
				case keyAddress:
					return proto.Marshal(signAddr)
				}

				return nil, nil
			})

			ccAcl := cc.New()
			mockStub.GetFunctionAndParametersReturns("checkAddress", []string{testCase.testAddress})
			resp := ccAcl.Invoke(mockStub)

			// check result
			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				return
			}

			addrFromLedger := &pb.Address{}
			require.NoError(t, proto.Unmarshal(resp.GetPayload(), addrFromLedger))
			require.True(t, proto.Equal(addrFromLedger, &pb.Address{
				UserID:       "testUserID",
				Address:      hashed[:],
				IsIndustrial: true,
			}))
		})
	}
}
