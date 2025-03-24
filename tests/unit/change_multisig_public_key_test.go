package unit

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
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
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestChangeMultisigPublicKey(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description string
		newPubKey   string
		respStatus  int32
		errorMsg    string
	}{
		{
			description: "public key equal 43 symbols",
			newPubKey:   "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
			respStatus:  int32(shim.OK),
		},
		{
			description: "public key equal 44 symbols",
			newPubKey:   "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
			respStatus:  int32(shim.OK),
		},
		{
			description: "public key empty",
			newPubKey:   "",
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrEmptyNewKey,
		},
		{
			description: "public key more than 44 symbols",
			newPubKey:   "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV': '33'",
		},
		{
			description: "public key less than 43 symbols",
			newPubKey:   "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "incorrect len of decoded from base58 public key 'Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR': '31'",
		},

		{
			description: "public key wrong numeric zero",
			newPubKey:   "00000000000000000000000000000000",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key 00000000000000000000000000000000",
		},

		{
			description: "public key with special symbols",
			newPubKey:   "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
			respStatus:  int32(shim.ERROR),
			errorMsg:    "failed base58 decoding of key Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
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
			msg := sha3.Sum256([]byte("lalalala"))
			signature := string(common.HexEncodedSignature(base58.Decode(privateKeys[0]), msg[:]))

			// prepare
			var newPubKeys []string
			for i, pk := range pubKeys {
				if i == 0 {
					newPubKeys = append(newPubKeys, testCase.newPubKey)
				} else {
					newPubKeys = append(newPubKeys, pk)
				}
			}
			newSeparatedPubKeys := strings.Join(newPubKeys, "/")
			oldKey := pubKeys[0]
			pKeysString := strings.Join(pubKeys, "/")
			keysArrSorted, err := helpers.DecodeAndSort(pKeysString)
			require.NoError(t, err)
			hashedPksSortedOrder := sha3.Sum256(bytes.Join(keysArrSorted, []byte("")))
			addrEncoded := base58.CheckEncode(hashedPksSortedOrder[1:], hashedPksSortedOrder[0])
			hashedKeysInHex := hex.EncodeToString(hashedPksSortedOrder[:])
			// new msg
			newNonce := strconv.Itoa(int(time.Now().Unix()*1000 + 1))
			reason := common.DefaultReason
			reasonID := "1"
			validatorPublicKeys := make([]string, len(common.TestUsersDifferentKeyTypes))
			for i, validator := range common.TestUsersDifferentKeyTypes {
				validatorPublicKeys[i] = validator.PublicKey
			}
			message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnChangeMultisigPublicKey, addrEncoded, oldKey, newSeparatedPubKeys, reason, reasonID, newNonce}, validatorPublicKeys...), "")))

			signatures := make([]string, len(common.TestUsersDifferentKeyTypes))
			for i, validator := range common.TestUsersDifferentKeyTypes {
				signatures[i] = string(common.HexEncodedSignature(base58.Decode(validator.PrivateKey), message[:]))
			}
			args := append(append([]string{addrEncoded, oldKey, testCase.newPubKey, reason, reasonID, newNonce}, validatorPublicKeys...), signatures...)

			keyNonceMulti, err := shim.CreateCompositeKey(compositekey.NoncePrefix, []string{addrEncoded})
			keyAddrMulti, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{hashedKeysInHex})
			keyPkMulti, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{addrEncoded})

			signAddr := &pb.SignedAddress{
				Address: &pb.Address{
					UserID:     "",
					Address:    hashedPksSortedOrder[:],
					IsMultisig: true,
				},
				SignedTx: []string{
					common.FnAddMultisig, "3", nonce,
					pubKeys[0], pubKeys[1], pubKeys[2],
					signature, signature, signature,
				},
				SignaturePolicy: &pb.SignaturePolicy{
					N:       3,
					PubKeys: [][]byte{publicKeys[0].Bytes, publicKeys[1].Bytes, publicKeys[2].Bytes},
				},
			}

			sigmBytes, err := proto.Marshal(signAddr)
			require.NoError(t, err)

			state := make(map[string][]byte)
			state["__config"] = cfgBytes
			state[keyPkMulti] = []byte(hashedKeysInHex)
			state[keyAddrMulti] = sigmBytes

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				v, ok := state[s]
				if ok {
					return v, nil
				}

				return nil, nil
			})

			ccAcl := cc.New()
			mockStub.GetFunctionAndParametersReturns(common.FnChangeMultisigPublicKey, args)
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				require.LessOrEqual(t, mockStub.PutStateCallCount(), 1)
				return
			}

			require.Equal(t, 2, mockStub.DelStateCallCount())
			require.Equal(t, 3, mockStub.PutStateCallCount())
			key, val := mockStub.PutStateArgsForCall(0)
			require.Equal(t, keyNonceMulti, key)
			require.Equal(t, newNonce, new(big.Int).SetBytes(val).String())
		})
	}
}
