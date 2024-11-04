package unit

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/anoideaopen/acl/tests/unit/mock"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestAddUserSecp256k1PublicKey(t *testing.T) {
	t.Parallel()

	const (
		testKeyECDSA = "041d16de99a91959437215b163172a0402346557eabdcb71535c287cba153cea65241a13a33ed672abc3223305b7e240cc8782469612c6b1f59ba0007b0248ce52"
		testAddress  = "9xVBTc5LmtxJN5AEAacJu9wiLwcuLeW6uj2afzWKHQczc1dWG"
	)

	bytes, err := hex.DecodeString(testKeyECDSA)
	require.NoError(t, err)
	userPublicKey := base58.Encode(bytes)

	for _, testCase := range []struct {
		description    string
		testPubKey     string
		testAddress    string
		kycHash        string
		testUserID     string
		testPubKeyType string
		respStatus     int32
		errorMsg       string
		fnName         string
		isExist        bool
	}{
		{
			description:    "[negative] add user with wrong key type",
			testPubKey:     userPublicKey,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeEd25519,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "unexpected key length",
			fnName:         common.FnAddUser,
			isExist:        false,
		},
		{
			description:    "[negative] add user with wrong key length",
			testPubKey:     userPublicKey[:len(userPublicKey)-2],
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeSecp256k1,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "incorrect len of decoded from base58 public key",
			fnName:         common.FnAddUser,
			isExist:        false,
		},
		{
			description:    "add user with secp256k1 key",
			testPubKey:     userPublicKey,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeSecp256k1,
			respStatus:     int32(shim.OK),
			errorMsg:       "",
			fnName:         common.FnAddUserWithPublicKeyType,
			isExist:        false,
		},
		{
			description:    "[negative] add user with secp256k1 key again",
			testPubKey:     userPublicKey,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeSecp256k1,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "already exists",
			fnName:         common.FnAddUserWithPublicKeyType,
			isExist:        true,
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub := new(mock.ChaincodeStub)
			mockStub.GetTxIDReturns("0")
			cfgBytes, err := protojson.Marshal(common.TestInitConfig)
			require.NoError(t, err)
			mockStub.GetSignedProposalReturns(&peer.SignedProposal{}, nil)
			pCert, _ := pem.Decode([]byte(common.AdminCert))
			parsed, err := x509.ParseCertificate(pCert.Bytes)
			require.NoError(t, err)
			marshaledIdentity, err := common.MarshalIdentity(common.TestCreatorMSP, parsed.Raw)
			require.NoError(t, err)
			mockStub.GetCreatorReturns(marshaledIdentity, nil)
			mockStub.CreateCompositeKeyCalls(func(s string, i []string) (string, error) {
				return shim.CreateCompositeKey(s, i)
			})

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
			if testCase.fnName == common.FnAddUserWithPublicKeyType {
				args = append(args, testCase.testPubKeyType)
			}
			mockStub.GetFunctionAndParametersReturns(testCase.fnName, args)
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

func TestAddUserGostPublicKey(t *testing.T) {
	t.Parallel()

	const (
		testKeyGost = "b5d49053fdb30abf8f0a5d668639fef83d8ed21cb5e1f0a8ba7e8350a11ab02270955c29d0f384879bcd2d775867dd59b7514868fa48a86ed4652d2af58341cf"
		testAddress = "WkSoEbdqsUbkAgsACNpeufp9HUstrtqpRSya4gebsuNn1S17D"
	)

	bytes, err := hex.DecodeString(testKeyGost)
	require.NoError(t, err)
	userPublicKey := base58.Encode(bytes)

	for _, testCase := range []struct {
		description    string
		testPubKey     string
		testAddress    string
		kycHash        string
		testUserID     string
		testPubKeyType string
		respStatus     int32
		errorMsg       string
		fnName         string
	}{
		{
			description:    "[negative] add user with gost public key with wrong length",
			testPubKey:     userPublicKey[:len(userPublicKey)-2],
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeGost,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "incorrect len of decoded from base58 public key",
			fnName:         common.FnAddUserWithPublicKeyType,
		},
		{
			description:    "add user with gost public key",
			testPubKey:     userPublicKey,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeGost,
			respStatus:     int32(shim.OK),
			errorMsg:       "",
			fnName:         common.FnAddUserWithPublicKeyType,
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub := new(mock.ChaincodeStub)
			mockStub.GetTxIDReturns("0")
			cfgBytes, err := protojson.Marshal(common.TestInitConfig)
			require.NoError(t, err)
			mockStub.GetSignedProposalReturns(&peer.SignedProposal{}, nil)
			pCert, _ := pem.Decode([]byte(common.AdminCert))
			parsed, err := x509.ParseCertificate(pCert.Bytes)
			require.NoError(t, err)
			marshaledIdentity, err := common.MarshalIdentity(common.TestCreatorMSP, parsed.Raw)
			require.NoError(t, err)
			mockStub.GetCreatorReturns(marshaledIdentity, nil)
			mockStub.CreateCompositeKeyCalls(func(s string, i []string) (string, error) {
				return shim.CreateCompositeKey(s, i)
			})

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				switch s {
				case "__config":
					return cfgBytes, nil
				}

				return nil, nil
			})

			ccAcl := cc.New()
			args := []string{testCase.testPubKey, testCase.kycHash, testCase.testUserID, stateTrue}
			if testCase.fnName == common.FnAddUserWithPublicKeyType {
				args = append(args, testCase.testPubKeyType)
			}
			mockStub.GetFunctionAndParametersReturns(testCase.fnName, args)
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
