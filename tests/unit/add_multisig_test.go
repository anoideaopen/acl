package unit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/anoideaopen/foundation/core/types/big"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestAddMultisig(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description string
		respStatus  int32
		errorMsg    string
		prepare     func([]string, []string, []string, map[string][]byte, string) []string
	}{
		{
			description: "happy path",
			respStatus:  int32(shim.OK),
			errorMsg:    "",
		},
		{
			description: "fraud: duplicate signature of multisig member (wrong case)",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "duplicated public keys",
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				pubkeys[2] = pubkeys[1]
				signs[2] = signs[1]
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "not all members signed (wrong case)",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "counts of keys and signatures are not equal",
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				return append(append([]string{"3", nonce}, pubkeys...), signs[1:]...)
			},
		},
		{
			description: "with one fake signature (wrong case)",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "does not match the public key",
			prepare: func(pubkeys []string, signs []string, priv []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				hash := sha3.Sum256([]byte(strings.Join(append([]string{"lalalala", "3", nonce}, pubkeys...), "")))
				signs[2] = string(common.HexEncodedSignature(base58.Decode(priv[2]), hash[:]))
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "wrong number of signature policy",
			respStatus:  int32(shim.ERROR),
			errorMsg:    fmt.Sprintf(errs.ErrWrongNumberOfKeys, 3, 10),
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				return append(append([]string{"10", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "wrong number of parameters",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect number of arguments",
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				return []string{nonce}
			},
		},
		{
			description: "use duplicate nonce",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect nonce",
			prepare: func(pubkeys []string, signs []string, _ []string, state map[string][]byte, addressMulti string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				keyNonceMulti, _ := shim.CreateCompositeKey(compositekey.NoncePrefix, []string{addressMulti})
				nonceB, _ := new(big.Int).SetString(nonce, 10)
				state[keyNonceMulti] = nonceB.Bytes()
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "nonce less than exists",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "less than exists",
			prepare: func(pubkeys []string, signs []string, _ []string, state map[string][]byte, addressMulti string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				keyNonceMulti, _ := shim.CreateCompositeKey(compositekey.NoncePrefix, []string{addressMulti})
				nonceB, _ := new(big.Int).SetString(nonce, 10)
				state[keyNonceMulti] = nonceB.Bytes()
				return append(append([]string{"3", "1"}, pubkeys...), signs...)
			},
		},
		{
			description: "pub key equal 43 symbols",
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrRecordsNotFound,
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				pubkeys[1] = "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2"
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "pub key equal 44 symbols",
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrRecordsNotFound,
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				pubkeys[1] = "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z"
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "pub key empty",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "empty public key detected",
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				pubkeys[1] = ""
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "pub key more than 44 symbols",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV': '33'",
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				pubkeys[1] = "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV"
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "pub key less than 43 symbols",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR': '31'",
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				pubkeys[1] = "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR"
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "pub key wrong numeric zero",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key 00000000000000000000000000000000",
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				pubkeys[1] = "00000000000000000000000000000000"
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
		{
			description: "pub key with special symbols",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
			prepare: func(pubkeys []string, signs []string, _ []string, _ map[string][]byte, _ string) []string {
				nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
				pubkeys[1] = "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra"
				return append(append([]string{"3", nonce}, pubkeys...), signs...)
			},
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			publicKeys := make([]cc.PublicKey, 0, len(common.MockUsersKeys))
			pubKeys := make([]string, 0, len(common.MockUsersKeys))
			privateKeys := make([]string, 0, len(common.MockUsersKeys))
			for pubKey, privateKey := range common.MockUsersKeys {
				b, err := helpers.DecodeBase58PublicKey(pubKey)
				require.NoError(t, err)
				hashed := sha3.Sum256(b)

				pubKeys = append(pubKeys, pubKey)
				publicKeys = append(publicKeys, cc.PublicKey{
					InBase58:          pubKey,
					Bytes:             b,
					Hash:              hashed[:],
					HashInHex:         hex.EncodeToString(hashed[:]),
					HashInBase58Check: base58.CheckEncode(hashed[1:], hashed[0]),
					Type:              helpers.DefaultPublicKeyType(),
				})
				privateKeys = append(privateKeys, privateKey)
			}

			pubKeysBytes := make([][]byte, 0, len(pubKeys))
			for _, pubKey := range publicKeys {
				pubKeysBytes = append(pubKeysBytes, []byte(pubKey.InBase58))
			}

			nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
			message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisig, "3", nonce}, pubKeys...), "")))

			signatures := make([]string, 0, len(privateKeys))
			for _, privateKey := range privateKeys {
				signatures = append(signatures, string(common.HexEncodedSignature(base58.Decode(privateKey), message[:])))
			}

			info, err := proto.Marshal(&pb.AccountInfo{
				KycHash: kycHash,
			})
			require.NoError(t, err)

			// multi user
			var (
				keysBytesInOriginalOrder = make([][]byte, len(common.MockUsersKeys))
				keysBytesSorted          = make([][]byte, len(common.MockUsersKeys))
			)

			for i, key := range publicKeys {
				keysBytesInOriginalOrder[i] = key.Bytes
				keysBytesSorted[i] = key.Bytes
			}

			sort.Slice(
				keysBytesSorted,
				func(i, j int) bool {
					return bytes.Compare(keysBytesSorted[i], keysBytesSorted[j]) < 0
				},
			)

			hashedMulti := sha3.Sum256(bytes.Join(keysBytesSorted, []byte("")))
			addressMulti := base58.CheckEncode(hashedMulti[1:], hashedMulti[0])
			hashedKeysInHexMulti := hex.EncodeToString(hashedMulti[:])
			keyNonceMulti, err := shim.CreateCompositeKey(compositekey.NoncePrefix, []string{addressMulti})
			keyAddrMulti, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{hashedKeysInHexMulti})
			keyPkMulti, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{addressMulti})

			state := make(map[string][]byte)
			state["__config"] = cfgBytes
			for _, pubKey := range publicKeys {
				keyPkType, err := shim.CreateCompositeKey(compositekey.PublicKeyTypePrefix, []string{pubKey.HashInHex})
				require.NoError(t, err)
				state[keyPkType] = []byte(common.KeyTypeEd25519)

				keyAccountInfo, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{pubKey.HashInBase58Check})
				require.NoError(t, err)
				state[keyAccountInfo] = info

				signAddr, err := proto.Marshal(&pb.SignedAddress{
					Address: &pb.Address{
						UserID:       "testUserID",
						Address:      pubKey.Hash,
						IsIndustrial: true,
					},
				})
				require.NoError(t, err)
				keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{pubKey.HashInHex})
				require.NoError(t, err)
				state[keyAddress] = signAddr
			}

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				v, ok := state[s]
				if ok {
					return v, nil
				}

				return nil, nil
			})

			ccAcl := cc.New()
			args := append(append([]string{"3", nonce}, pubKeys...), signatures...)
			if testCase.prepare != nil {
				args = testCase.prepare(pubKeys, signatures, privateKeys, state, addressMulti)
			}

			mockStub.GetFunctionAndParametersReturns(common.FnAddMultisig, args)
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				require.LessOrEqual(t, mockStub.PutStateCallCount(), 1)
				return
			}

			require.Equal(t, 3, mockStub.PutStateCallCount())
			key, val := mockStub.PutStateArgsForCall(0)
			require.Equal(t, keyNonceMulti, key)
			require.Equal(t, nonce, new(big.Int).SetBytes(val).String())

			key, val = mockStub.PutStateArgsForCall(1)
			require.Equal(t, keyAddrMulti, key)
			signMultiAddr := &pb.SignedAddress{}
			err = proto.Unmarshal(val, signMultiAddr)
			require.NoError(t, err)
			require.True(t, proto.Equal(&pb.SignedAddress{
				Address: &pb.Address{
					UserID:     "",
					Address:    hashedMulti[:],
					IsMultisig: true,
				},
				SignedTx: []string{common.FnAddMultisig, "3", nonce,
					pubKeys[0], pubKeys[1], pubKeys[2],
					signatures[0], signatures[1], signatures[2],
				},
				SignaturePolicy: &pb.SignaturePolicy{
					N:       3,
					PubKeys: keysBytesInOriginalOrder,
				},
			}, signMultiAddr))

			key, val = mockStub.PutStateArgsForCall(2)
			require.Equal(t, keyPkMulti, key)
			require.Equal(t, hashedKeysInHexMulti, string(val))
		})
	}
}
