package unit

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/anoideaopen/acl/tests/unit/mock"
	"github.com/anoideaopen/foundation/core/types/big"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

func TestAdditionalKey(t *testing.T) {
	t.Parallel()

	tags := `["tag1", "tag2", "tag3"]`
	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	additionalPublicKey := "4PEK3x3CZZtQC9AJtqCVt5RFJgjt5s6PqS7JL7cCboBfYJMiufaMFo4YCp7gKUQ8AXGM5Wb9i15617SS7hhr3P7M"

	keyPk, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{common.TestAddr})
	require.NoError(t, err)
	keyAccountInfo, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{common.TestAddr})
	require.NoError(t, err)
	keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{common.TestAddrHashInHex})
	require.NoError(t, err)
	keyNonce, err := shim.CreateCompositeKey(compositekey.NoncePrefix, []string{common.TestAddr})
	require.NoError(t, err)
	keyAdditionalKeyParent, err := shim.CreateCompositeKey(compositekey.AdditionalKeyParentPrefix, []string{additionalPublicKey})

	info, err := proto.Marshal(&pb.AccountInfo{
		KycHash: kycHash,
	})
	require.NoError(t, err)

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
	signAddrBytes, err := proto.Marshal(&pb.SignedAddress{
		Address: &pb.Address{
			UserID:       "testUserID",
			Address:      hashed[:],
			IsIndustrial: true,
		},
	})
	require.NoError(t, err)

	signAddr1 := &pb.SignedAddress{
		Address: &pb.Address{
			UserID:       "testUserID",
			Address:      hashed[:],
			IsIndustrial: true,
		},
		AdditionalKeys: []*pb.AdditionalKey{
			{
				PublicKeyBase58: additionalPublicKey,
				Labels:          []string{"tag1", "tag2", "tag3"},
			},
		},
	}
	signAddrBytes1, err := proto.Marshal(signAddr1)
	require.NoError(t, err)

	for _, testCase := range []struct {
		description string
		fn          string
		args        func() []string
		respStatus  int32
		errorMsg    string
		prepare     func(state map[string][]byte)
		check       func(t *testing.T, mockStub *mock.ChaincodeStub)
	}{
		{
			description: "add additional key - ok",
			fn:          common.FnAddAdditionalKey,
			args: func() []string {
				// Composing a message to be signed.
				validatorPublicKeys := make([]string, 0, len(common.TestUsersDifferentKeyTypes))
				for publicKey := range common.MockValidatorsKeys {
					validatorPublicKeys = append(validatorPublicKeys, publicKey)
				}
				messageElements := []string{
					common.FnAddAdditionalKey,
					common.TestAddr,
					additionalPublicKey,
					tags,
					nonce,
				}
				messageElements = append(messageElements, validatorPublicKeys...)
				// Creating a hash of the message.
				messageDigest := sha3.Sum256([]byte(strings.Join(messageElements, "")))

				// Signing the message.
				_, validatorSignatures := common.GenerateTestValidatorSignatures(validatorPublicKeys, messageDigest[:])

				for _, signature := range validatorSignatures {
					messageElements = append(messageElements, string(signature))
				}

				return messageElements[1:]
			},
			respStatus: int32(shim.OK),
			prepare: func(state map[string][]byte) {
				state[keyPk] = []byte(common.TestAddrHashInHex)
				state[keyAccountInfo] = info
				state[keyAddress] = signAddrBytes
			},
			check: func(t *testing.T, mockStub *mock.ChaincodeStub) {
				require.Equal(t, 3, mockStub.PutStateCallCount())

				key, val := mockStub.PutStateArgsForCall(0)
				require.Equal(t, keyNonce, key)
				require.Equal(t, nonce, new(big.Int).SetBytes(val).String())

				key, val = mockStub.PutStateArgsForCall(1)
				require.Equal(t, keyAddress, key)
				signAddrExp := &pb.SignedAddress{}
				err = proto.Unmarshal(val, signAddrExp)
				require.NoError(t, err)
				require.True(t, proto.Equal(signAddrExp, signAddr1))

				key, val = mockStub.PutStateArgsForCall(2)
				require.Equal(t, keyAdditionalKeyParent, key)
				require.Equal(t, common.TestAddr, string(val))
			},
		},
		{
			description: "remove additional key - ok",
			fn:          common.FnRemoveAdditionalKey,
			args: func() []string {
				// Composing a message to be signed.
				validatorPublicKeys := make([]string, 0, len(common.TestUsersDifferentKeyTypes))
				for publicKey := range common.MockValidatorsKeys {
					validatorPublicKeys = append(validatorPublicKeys, publicKey)
				}
				messageElements := []string{
					common.FnRemoveAdditionalKey,
					common.TestAddr,
					additionalPublicKey,
					nonce,
				}
				messageElements = append(messageElements, validatorPublicKeys...)
				// Creating a hash of the message.
				messageDigest := sha3.Sum256([]byte(strings.Join(messageElements, "")))

				// Signing the message.
				_, validatorSignatures := common.GenerateTestValidatorSignatures(validatorPublicKeys, messageDigest[:])

				for _, signature := range validatorSignatures {
					messageElements = append(messageElements, string(signature))
				}

				return messageElements[1:]
			},
			respStatus: int32(shim.OK),
			prepare: func(state map[string][]byte) {
				state[keyPk] = []byte(common.TestAddrHashInHex)
				state[keyAccountInfo] = info
				state[keyAddress] = signAddrBytes1
				state[keyAdditionalKeyParent] = []byte(common.TestAddr)
			},
			check: func(t *testing.T, mockStub *mock.ChaincodeStub) {
				require.Equal(t, 2, mockStub.PutStateCallCount())

				key, val := mockStub.PutStateArgsForCall(0)
				require.Equal(t, keyNonce, key)
				require.Equal(t, nonce, new(big.Int).SetBytes(val).String())

				key, val = mockStub.PutStateArgsForCall(1)
				require.Equal(t, keyAddress, key)
				signAddrExp := &pb.SignedAddress{}
				err = proto.Unmarshal(val, signAddrExp)
				require.NoError(t, err)
				require.True(t, proto.Equal(signAddr, signAddrExp))

				require.Equal(t, 1, mockStub.DelStateCallCount())

				key = mockStub.DelStateArgsForCall(0)
				require.Equal(t, keyAdditionalKeyParent, key)
			},
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			state := make(map[string][]byte)
			state["__config"] = cfgBytes

			if testCase.prepare != nil {
				testCase.prepare(state)
			}

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				v, ok := state[s]
				if ok {
					return v, nil
				}

				return nil, nil
			})

			ccAcl := cc.New()
			mockStub.GetFunctionAndParametersReturns(testCase.fn, testCase.args())
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				require.LessOrEqual(t, mockStub.PutStateCallCount(), 1)
				return
			}

			if testCase.check != nil {
				testCase.check(t, mockStub)
			}
		})
	}
}
