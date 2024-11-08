package unit

import (
	"bytes"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestCheckKeys(t *testing.T) {
	t.Parallel()

	multiBubKey := common.TestUsers[0].PublicKey + "/" +
		common.TestUsers[1].PublicKey + "/" +
		common.TestUsers[2].PublicKey

	keys := strings.Split(multiBubKey, "/")

	var (
		keysBytesSorted          [][]byte
		keysBytesInOriginalOrder [][]byte
	)
	for _, key := range keys {
		b, err := helpers.DecodeBase58PublicKey(key)
		require.NoError(t, err)
		keysBytesSorted = append(keysBytesSorted, b)
		keysBytesInOriginalOrder = append(keysBytesInOriginalOrder, b)
	}

	sort.Slice(
		keysBytesSorted,
		func(i, j int) bool {
			return bytes.Compare(keysBytesSorted[i], keysBytesSorted[j]) < 0
		},
	)

	hashedM := sha3.Sum256(bytes.Join(keysBytesSorted, []byte("")))
	// addressM := base58.CheckEncode(hashedM[1:], hashedM[0])
	hashedKeysInHexM := hex.EncodeToString(hashedM[:])

	for _, testCase := range []struct {
		description string
		testPubKey  string
		testAddress string
		kycHash     string
		testUserID  string
		respStatus  int32
		errorMsg    string
		keyTypes    []pb.KeyType
		getFn       func(s string) ([]byte, error)
		aclRespFn   func() *pb.AclResponse
	}{
		{
			description: "public key equal 43 symbols",
			testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
			testAddress: common.TestWrongAddress,
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.OK),
			errorMsg:    "",
			keyTypes:    []pb.KeyType{pb.KeyType_ed25519},
			getFn: func(s string) ([]byte, error) {
				info := &pb.AccountInfo{
					KycHash: kycHash,
				}

				b, err := helpers.DecodeBase58PublicKey("Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2")
				require.NoError(t, err)
				hashed := sha3.Sum256(b)
				signAddr := &pb.SignedAddress{
					Address: &pb.Address{
						UserID:       "testUserID",
						Address:      hashed[:],
						IsIndustrial: true,
					},
				}

				keyPkType, err := shim.CreateCompositeKey(compositekey.PublicKeyTypePrefix, []string{"a3273cba2537a1d5101629255a99c8779612f8e6fffe005fdf6af5290ca061b6"})
				require.NoError(t, err)
				keyAccountInfo, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{"2ErXpMHdKbAVhVYZ28F9eSoZ1WYEYLhodeJNUxXyGyDeL9xKqt"})
				require.NoError(t, err)
				keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{"a3273cba2537a1d5101629255a99c8779612f8e6fffe005fdf6af5290ca061b6"})
				require.NoError(t, err)
				switch s {
				case keyPkType:
					return []byte(common.KeyTypeEd25519), nil
				case keyAccountInfo:
					return proto.Marshal(info)
				case keyAddress:
					return proto.Marshal(signAddr)
				}
				return nil, nil
			},
			aclRespFn: func() *pb.AclResponse {
				b, err := helpers.DecodeBase58PublicKey("Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2")
				require.NoError(t, err)
				hashed := sha3.Sum256(b)

				return &pb.AclResponse{
					Account: &pb.AccountInfo{
						KycHash: kycHash,
					},
					Address: &pb.SignedAddress{
						Address: &pb.Address{
							UserID:       testUserID,
							Address:      hashed[:],
							IsIndustrial: true,
						},
					},
					KeyTypes: []pb.KeyType{pb.KeyType_ed25519},
				}
			},
		},
		{
			description: "public key equal 44 symbols",
			testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
			testAddress: "FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.OK),
			errorMsg:    "",
			keyTypes:    []pb.KeyType{pb.KeyType_ed25519},
			getFn: func(s string) ([]byte, error) {
				info := &pb.AccountInfo{
					KycHash: kycHash,
				}

				b, err := helpers.DecodeBase58PublicKey("Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z")
				require.NoError(t, err)
				hashed := sha3.Sum256(b)
				signAddr := &pb.SignedAddress{
					Address: &pb.Address{
						UserID:       "testUserID",
						Address:      hashed[:],
						IsIndustrial: true,
					},
				}

				keyPkType, err := shim.CreateCompositeKey(compositekey.PublicKeyTypePrefix, []string{"2132448f85aac86548adbec3f439233bda4e556991b0dd35698520c82cf829dd"})
				require.NoError(t, err)
				keyAccountInfo, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{"FcxURVVuLyR7bMJYYeW34HDKdzEvcMDwfWo1wS9oYmCaeps9N"})
				require.NoError(t, err)
				keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{"2132448f85aac86548adbec3f439233bda4e556991b0dd35698520c82cf829dd"})
				require.NoError(t, err)
				switch s {
				case keyPkType:
					return []byte(common.KeyTypeEd25519), nil
				case keyAccountInfo:
					return proto.Marshal(info)
				case keyAddress:
					return proto.Marshal(signAddr)
				}
				return nil, nil
			},
			aclRespFn: func() *pb.AclResponse {
				b, err := helpers.DecodeBase58PublicKey("Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z")
				require.NoError(t, err)
				hashed := sha3.Sum256(b)

				return &pb.AclResponse{
					Account: &pb.AccountInfo{
						KycHash: kycHash,
					},
					Address: &pb.SignedAddress{
						Address: &pb.Address{
							UserID:       testUserID,
							Address:      hashed[:],
							IsIndustrial: true,
						},
					},
					KeyTypes: []pb.KeyType{pb.KeyType_ed25519},
				}
			},
		},
		{
			description: "public key empty",
			testPubKey:  "",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrEmptyPubKey,
		},
		{
			description: "public key more than 44 symbols",
			testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV': '33'",
		},
		{
			description: "public key less than 43 symbols",
			testPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR': '31'",
		},
		{
			description: "with special symbol",
			testPubKey:  "/",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "encoded base 58 public key is empty, input: '/'",
		},
		{
			description: "duplicate keys",
			testPubKey:  common.PubKey + "/" + common.PubKey,
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "duplicated public keys",
		},
		{
			description: "public key wrong numeric zero",
			testPubKey:  "00000000000000000000000000000000",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key 00000000000000000000000000000000",
		},
		{
			description: "public key with special symbols",
			testPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
			testAddress: "",
			kycHash:     kycHash,
			testUserID:  testUserID,
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		},
		{
			description: "multi keys",
			testPubKey: common.TestUsers[0].PublicKey + "/" +
				common.TestUsers[1].PublicKey + "/" +
				common.TestUsers[2].PublicKey,
			testAddress: "K7n4n5Pn8r6EK83UaUnzk56DLoGywjYQfYxM4hVVSp9sBau42",
			respStatus:  int32(shim.OK),
			kycHash:     kycHash,
			testUserID:  "",
			keyTypes: []pb.KeyType{
				pb.KeyType(pb.KeyType_value[common.TestUsers[0].KeyType]),
				pb.KeyType(pb.KeyType_value[common.TestUsers[1].KeyType]),
				pb.KeyType(pb.KeyType_value[common.TestUsers[2].KeyType]),
			},
			getFn: func(s string) ([]byte, error) {
				info := &pb.AccountInfo{
					KycHash: kycHash,
				}

				signAddr := &pb.SignedAddress{
					Address: &pb.Address{
						UserID:       "",
						Address:      hashedM[:],
						IsIndustrial: true,
					},
					SignedTx: []string{"addMultisig", "3", "1731068306000",
						"A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4",
						"5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5",
						"6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4",
						"9437e939a570989dc92b6c8eb771edea3d45d15ef084c7c48dfac42a0b2cb4b16368ff85d63681465628fedfd4611e4d3616f79a2d33caf46d09e57682bb3007",
						"4ce2aa0e7126ff89e86ea34a9a7880b95af9c050288f9f8eb8a88913920b65e9cb5c678e4d690c4bdb058fdb60129f8f8bbccb4515511e0723e08ef709d0a302",
						"bcaa4c8a74ccfe116d9a36ec53b5a222b588adf38041d9bad7c987f957978ce23332f025ee4940e3725ffb3767a75c3ec13081fcf52459e5263c846e084cd20e",
					},
					SignaturePolicy: &pb.SignaturePolicy{
						N:       3,
						PubKeys: keysBytesInOriginalOrder,
					},
				}

				bytes1, err := helpers.DecodeBase58PublicKey("A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4")
				require.NoError(t, err)
				hashed1 := sha3.Sum256(bytes1)
				signAddr1 := &pb.SignedAddress{
					Address: &pb.Address{
						UserID:       "testUserID",
						Address:      hashed1[:],
						IsIndustrial: true,
					},
				}

				bytes2, err := helpers.DecodeBase58PublicKey("5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5")
				require.NoError(t, err)
				hashed2 := sha3.Sum256(bytes2)
				signAddr2 := &pb.SignedAddress{
					Address: &pb.Address{
						UserID:       "testUserID",
						Address:      hashed2[:],
						IsIndustrial: true,
					},
				}

				bytes3, err := helpers.DecodeBase58PublicKey("6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4")
				require.NoError(t, err)
				hashed3 := sha3.Sum256(bytes3)
				signAddr3 := &pb.SignedAddress{
					Address: &pb.Address{
						UserID:       "testUserID",
						Address:      hashed3[:],
						IsIndustrial: true,
					},
				}

				keyPkType1, err := shim.CreateCompositeKey(compositekey.PublicKeyTypePrefix, []string{"152071d5e3aebe5361c51a048547d0b54fd0b83a889c046ef3025a5fa7f0b0d8"})
				require.NoError(t, err)
				keyPkType2, err := shim.CreateCompositeKey(compositekey.PublicKeyTypePrefix, []string{"c39bdb593f69dc7d1a832bd930683323f6d90e2d34a30e1b16555630e07cb5e6"})
				require.NoError(t, err)
				keyPkType3, err := shim.CreateCompositeKey(compositekey.PublicKeyTypePrefix, []string{"8b29f07e4871aa531aac581b0153a6a04af1a9d62c720ee6d5cad351d8e5c12a"})
				require.NoError(t, err)

				keyAccountInfo1, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{"AJewXqJpv8wkPw4HJ9BLrp7rcBENADtvWUsA6QxdN9dn14Axg"})
				require.NoError(t, err)
				keyAccountInfo2, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{"2V9ZkXc2UG8rfbCLqXwQDifNXRNdDfFedrwcgfWm4WWGpconSK"})
				require.NoError(t, err)
				keyAccountInfo3, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{"24HkgcWhV7YEJHtbfwrn8vpDVA41FngSUQy2nbCi6KPwCU7VCR"})
				require.NoError(t, err)

				keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{hashedKeysInHexM})
				require.NoError(t, err)
				keyAddress1, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{"152071d5e3aebe5361c51a048547d0b54fd0b83a889c046ef3025a5fa7f0b0d8"})
				require.NoError(t, err)
				keyAddress2, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{"c39bdb593f69dc7d1a832bd930683323f6d90e2d34a30e1b16555630e07cb5e6"})
				require.NoError(t, err)
				keyAddress3, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{"8b29f07e4871aa531aac581b0153a6a04af1a9d62c720ee6d5cad351d8e5c12a"})
				require.NoError(t, err)

				switch s {
				case keyPkType1, keyPkType2, keyPkType3:
					return []byte(common.KeyTypeEd25519), nil
				case keyAccountInfo1, keyAccountInfo2, keyAccountInfo3:
					return proto.Marshal(info)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyAddress1:
					return proto.Marshal(signAddr1)
				case keyAddress2:
					return proto.Marshal(signAddr2)
				case keyAddress3:
					return proto.Marshal(signAddr3)
				}
				return nil, nil
			},
			aclRespFn: func() *pb.AclResponse {
				return &pb.AclResponse{
					Account: &pb.AccountInfo{
						KycHash: kycHash,
					},
					Address: &pb.SignedAddress{
						Address: &pb.Address{
							UserID:       "",
							Address:      hashedM[:],
							IsIndustrial: true,
						},
						SignedTx: []string{"addMultisig", "3", "1731068306000",
							"A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4",
							"5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5",
							"6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4",
							"9437e939a570989dc92b6c8eb771edea3d45d15ef084c7c48dfac42a0b2cb4b16368ff85d63681465628fedfd4611e4d3616f79a2d33caf46d09e57682bb3007",
							"4ce2aa0e7126ff89e86ea34a9a7880b95af9c050288f9f8eb8a88913920b65e9cb5c678e4d690c4bdb058fdb60129f8f8bbccb4515511e0723e08ef709d0a302",
							"bcaa4c8a74ccfe116d9a36ec53b5a222b588adf38041d9bad7c987f957978ce23332f025ee4940e3725ffb3767a75c3ec13081fcf52459e5263c846e084cd20e",
						},
						SignaturePolicy: &pb.SignaturePolicy{
							N:       3,
							PubKeys: keysBytesInOriginalOrder,
						},
					},
					KeyTypes: []pb.KeyType{
						pb.KeyType(pb.KeyType_value[common.TestUsers[0].KeyType]),
						pb.KeyType(pb.KeyType_value[common.TestUsers[1].KeyType]),
						pb.KeyType(pb.KeyType_value[common.TestUsers[2].KeyType]),
					},
				}
			},
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				switch s {
				case "__config":
					return cfgBytes, nil
				}

				if testCase.getFn != nil {
					return testCase.getFn(s)
				}

				return nil, nil
			})

			ccAcl := cc.New()
			mockStub.GetFunctionAndParametersReturns(common.FnCheckKeys, []string{testCase.testPubKey})
			resp := ccAcl.Invoke(mockStub)

			// check result
			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				return
			}

			aclResponse := &pb.AclResponse{}
			require.NoError(t, proto.Unmarshal(resp.GetPayload(), aclResponse))
			require.True(t, proto.Equal(aclResponse, testCase.aclRespFn()))
		})
	}
}
