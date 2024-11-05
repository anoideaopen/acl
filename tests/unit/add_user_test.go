package unit

import (
	"encoding/hex"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"

	//nolint:staticcheck
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

const (
	kycHash    = "kycHash"
	testUserID = "testUserID"
	stateTrue  = "true"
)

func TestAddUserPubKey(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description string
		testPubKey  string
		testAddress string
		kycHash     string
		testUserID  string
		respStatus  int32
		errorMsg    string
		isExist     bool
	}{
		{
			description: "pub key 43 symbols",
			testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
			testAddress: common.TestWrongAddress,
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.OK),
			errorMsg:    "",
			isExist:     false,
		},
		{
			description: "pub key 44 symbols",
			testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
			testAddress: "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.OK),
			errorMsg:    "",
			isExist:     false,
		},
		{
			description: "pub key empty",
			testPubKey:  "",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "encoded base 58 public key is empty",
			isExist:     false,
		},
		{
			description: "pub key more than 44 symbols",
			testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV': '33'",
			isExist:     false,
		},
		{
			description: "pub key less than 43 symbols",
			testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR': '31'",
			isExist:     false,
		},
		{
			description: "pub key wrong string",
			testPubKey:  "AbracadabraAbracadabraAbracadabraAbracada0oI",
			testAddress: "2i1EhJeQG3hyXZiv64XPNAHFhHRPbXFw6Tt6P6ewV4Q98KaKZM",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key AbracadabraAbracadabraAbracadabraAbracada0oI",
			isExist:     false,
		},
		{
			description: "pub key wrong numeric",
			testPubKey:  "01111111111111111111111111111111",
			testAddress: "2CkjXDKfcFFMVdLP9QzBBqFG8PGUxaERwhyvrh4BLsPNwW1T6F",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key 01111111111111111111111111111111",
			isExist:     false,
		},
		{
			description: "pub key wrong numeric zero",
			testPubKey:  "00000000000000000000000000000000",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key 00000000000000000000000000000000",
			isExist:     false,
		},
		{
			description: "pub key with special symbols",
			testPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
			isExist:     false,
		},
		{
			description: "pub key empty kyc hash",
			testPubKey:  common.PubKey,
			testAddress: common.TestAddr,
			kycHash:     "",
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "empty kyc hash",
			isExist:     false,
		},
		{
			description: "pub key empty user id",
			testPubKey:  common.PubKey,
			testAddress: common.TestAddr,
			kycHash:     kycHash,
			testUserID:  "",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "empty userID",
			isExist:     false,
		},
		{
			description: "pub key again already exist",
			testPubKey:  common.PubKey,
			testAddress: common.TestAddr,
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "already exists",
			isExist:     true,
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NuwMockStub(t)

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				switch s {
				case "__config":
					return cfgBytes, nil
				}

				if testCase.isExist {
					b, err := helpers.DecodeBase58PublicKey(testCase.testPubKey)
					require.NoError(t, err)
					hashed := sha3.Sum256(b)
					hashAddress := hex.EncodeToString(hashed[:])

					key, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{hashAddress})
					require.NoError(t, err)

					if s != key {
						return nil, nil
					}

					signAddr := &pb.SignedAddress{
						Address: &pb.Address{
							UserID:       "testUserID",
							Address:      hashed[:],
							IsIndustrial: true,
							IsMultisig:   false,
						},
					}
					return proto.Marshal(signAddr)
				}

				return nil, nil
			})

			ccAcl := cc.New()
			args := []string{testCase.testPubKey, testCase.kycHash, testCase.testUserID, stateTrue}
			mockStub.GetFunctionAndParametersReturns(common.FnAddUser, args)
			resp := ccAcl.Invoke(mockStub)

			// check result
			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				require.Equal(t, mockStub.PutStateCallCount(), 0)
				return
			}

			require.Equal(t, 4, mockStub.PutStateCallCount())
			_, valState := mockStub.PutStateArgsForCall(0)
			signAddr := &pb.SignedAddress{}
			require.NoError(t, proto.Unmarshal(valState, signAddr))
			require.Equal(t, signAddr.GetAddress().UserID, testCase.testUserID)

			_, valState = mockStub.PutStateArgsForCall(3)
			addrFromLedger := &pb.AccountInfo{}
			require.NoError(t, proto.Unmarshal(valState, addrFromLedger))
			require.True(t, proto.Equal(addrFromLedger, &pb.AccountInfo{
				KycHash: "kycHash",
			}))
		})
	}
}
