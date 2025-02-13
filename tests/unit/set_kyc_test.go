package unit

import (
	"crypto/sha3"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/anoideaopen/acl/tests/unit/mock"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSetKyc(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description string
		testAddress string
		newKYC      string
		respStatus  int32
		errorMsg    string
	}{
		{
			description: "set kyc true",
			testAddress: common.TestAddr,
			newKYC:      "newKychash",
			respStatus:  200,
			errorMsg:    "",
		},
		{
			description: "set kyc empty address",
			testAddress: "",
			newKYC:      "newKychash",
			respStatus:  500,
			errorMsg:    errs.ErrEmptyAddress,
		},
		{
			description: "set kyc wrong address",
			testAddress: common.TestWrongAddress,
			newKYC:      "newKychash",
			respStatus:  500,
			errorMsg:    "account info for address " + common.TestWrongAddress + " is empty",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			info := &pb.AccountInfo{
				KycHash: kycHash,
			}
			key, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{common.TestAddr})
			require.NoError(t, err)
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
			resp := setKyc(ccAcl, mockStub, testCase.testAddress, testCase.newKYC)
			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				require.Less(t, mockStub.PutStateCallCount(), 2)
				return
			}

			require.Equal(t, 2, mockStub.PutStateCallCount())
			keyState, valState := mockStub.PutStateArgsForCall(1)
			require.Equal(t, key, keyState)

			// check address
			addrFromLedger := &pb.AccountInfo{}
			require.NoError(t, proto.Unmarshal(valState, addrFromLedger))
			require.True(t, proto.Equal(addrFromLedger, &pb.AccountInfo{
				KycHash: testCase.newKYC,
			}))
		})
	}
}

func setKyc(cc *cc.ACL, mockStub *mock.ChaincodeStub, addr string, kyc string) *peer.Response {
	// change KYC
	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	pKeys := make([]string, 0, len(common.TestUsersDifferentKeyTypes))
	for _, user := range common.TestUsersDifferentKeyTypes {
		pKeys = append(pKeys, user.PublicKey)
	}

	message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnSetKYC, addr, kyc, nonce}, pKeys...), "")))

	vSignatures := make([]string, 0, len(pKeys))
	for _, pubKey := range pKeys {
		sKey := common.MockValidatorsKeys[pubKey]
		vSignatures = append(vSignatures, string(common.HexEncodedSignature(base58.Decode(sKey), message[:])))
	}

	args := []string{addr, kyc, nonce}
	args = append(args, pKeys...)
	args = append(args, vSignatures...)
	mockStub.GetFunctionAndParametersReturns(common.FnSetKYC, args)
	return cc.Invoke(mockStub)
}
