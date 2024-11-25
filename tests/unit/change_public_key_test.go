package unit

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/anoideaopen/foundation/core/types/big"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestChangePublicKey(t *testing.T) {
	t.Parallel()

	reasonID := "1"
	newPubKey := "94EdE9iZRzU9mUiVDNxYKKWymHeBxHR8mA8AetFrg8m4"

	for _, testCase := range []struct {
		description string
		respStatus  int32
		errorMsg    string
		newPubKey   string
		prepare     func([]string) []string
	}{
		{
			description: "fraud: duplicate signature (wrong case)",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "duplicate validators signatures are not allowed",
			newPubKey:   newPubKey,
			prepare: func(pubkeys []string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				args := []string{
					common.FnChangePublicKey,
					common.TestAddr,
					common.DefaultReason,
					reasonID,
					newPubKey,
					nonce,
				}
				pubkeys[2] = pubkeys[1]

				args = append(args, pubkeys...)
				message := sha3.Sum256([]byte(strings.Join(args, "")))
				_, vSignatures := common.GenerateTestValidatorSignatures(pubkeys, message[:])

				var signatures []string
				for _, signature := range vSignatures {
					signatures = append(signatures, string(signature))
				}

				args = append(args, signatures...)

				return args
			},
		},
		{
			description: "not all members signed (wrong case)",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "uneven number of public keys and signatures provided",
			newPubKey:   newPubKey,
			prepare: func(pubkeys []string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				args := []string{
					common.FnChangePublicKey,
					common.TestAddr,
					common.DefaultReason,
					reasonID,
					newPubKey,
					nonce,
				}
				pubkeys[2] = pubkeys[1]

				args = append(args, pubkeys...)
				message := sha3.Sum256([]byte(strings.Join(args, "")))
				_, vSignatures := common.GenerateTestValidatorSignatures(pubkeys, message[:])

				var signatures []string
				for _, signature := range vSignatures {
					signatures = append(signatures, string(signature))
				}

				args = append(args, signatures[:len(signatures)-1]...)

				return args
			},
		},
		{
			description: "incorrect new key input (wrong case)",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key blabla",
			newPubKey:   "blabla",
		},
		{
			description: "pub key equal 43 symbols",
			respStatus:  int32(shim.OK),
			errorMsg:    "",
			newPubKey:   "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		},
		{
			description: "pub key equal 44 symbols",
			respStatus:  int32(shim.OK),
			errorMsg:    "",
			newPubKey:   "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		},
		{
			description: "pub key empty",
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrEmptyNewKey,
			newPubKey:   "",
		},
		{
			description: "pub key more than 44 symbols",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV': '33'",
			newPubKey:   "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
		},
		{
			description: "pub key less than 43 symbols",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR': '31'",
			newPubKey:   "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
		},
		{
			description: "pub key wrong numeric zero",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key 00000000000000000000000000000000",
			newPubKey:   "00000000000000000000000000000000",
		},
		{
			description: "pub key with special symbols",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
			newPubKey:   "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			pKeys := make([]string, len(common.TestUsersDifferentKeyTypes))
			for i, user := range common.TestUsersDifferentKeyTypes {
				pKeys[i] = user.PublicKey
			}
			nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
			args := []string{
				common.FnChangePublicKey,
				common.TestAddr,
				common.DefaultReason,
				reasonID,
				testCase.newPubKey,
				nonce,
			}

			args = append(args, pKeys...)
			message := sha3.Sum256([]byte(strings.Join(args, "")))
			_, vSignatures := common.GenerateTestValidatorSignatures(pKeys, message[:])

			var signatures []string
			for _, signature := range vSignatures {
				signatures = append(signatures, string(signature))
			}

			args = append(args, signatures...)

			if testCase.prepare != nil {
				args = testCase.prepare(pKeys)
			}

			keyPk, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{common.TestAddr})
			require.NoError(t, err)
			keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{common.TestAddrHashInHex})
			require.NoError(t, err)
			keyNonce, err := shim.CreateCompositeKey(compositekey.NoncePrefix, []string{common.TestAddr})
			require.NoError(t, err)

			hashed := sha3.Sum256(base58.Decode(common.PubKey))
			signAddr, err := proto.Marshal(&pb.SignedAddress{
				Address: &pb.Address{
					UserID:       "testUserID",
					Address:      hashed[:],
					IsIndustrial: true,
				},
			})
			require.NoError(t, err)

			state := make(map[string][]byte)
			state["__config"] = cfgBytes
			state[keyPk] = []byte(common.TestAddrHashInHex)
			state[keyAddress] = signAddr

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				v, ok := state[s]
				if ok {
					return v, nil
				}

				return nil, nil
			})

			ccAcl := cc.New()
			mockStub.GetFunctionAndParametersReturns(common.FnChangePublicKey, args[1:])
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				require.LessOrEqual(t, mockStub.PutStateCallCount(), 1)
				return
			}

			require.Equal(t, 2, mockStub.DelStateCallCount())
			key := mockStub.DelStateArgsForCall(0)
			require.Equal(t, keyAddress, key)
			key = mockStub.DelStateArgsForCall(1)
			require.Equal(t, keyPk, key)

			require.Equal(t, 3, mockStub.PutStateCallCount())
			key, val := mockStub.PutStateArgsForCall(0)
			require.Equal(t, keyNonce, key)
			require.Equal(t, nonce, new(big.Int).SetBytes(val).String())

			key, val = mockStub.PutStateArgsForCall(2)
			require.Equal(t, keyPk, key)
			keyAddress, err = shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{string(val)})
			require.NoError(t, err)

			key, val = mockStub.PutStateArgsForCall(1)
			require.Equal(t, keyAddress, key)
			signAddrGet := &pb.SignedAddress{}
			err = proto.Unmarshal(val, signAddrGet)
			require.NoError(t, err)
			require.True(t, proto.Equal(&pb.SignedAddress{
				Address: &pb.Address{
					UserID:       "testUserID",
					Address:      hashed[:],
					IsIndustrial: true,
				},
				SignedTx: []string{common.FnChangePublicKey,
					common.TestAddr,
					common.DefaultReason,
					reasonID,
					testCase.newPubKey,
					nonce,
					pKeys[0], pKeys[1], pKeys[2],
					signatures[0], signatures[1], signatures[2],
				},
				Reason:   common.DefaultReason,
				ReasonId: int32(1),
			}, signAddrGet))
		})
	}
}
