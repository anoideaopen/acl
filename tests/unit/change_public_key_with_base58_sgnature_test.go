package unit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/acl/tests/unit/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	pbBuf "google.golang.org/protobuf/proto"
)

func TestChangePublicKeyWithBase58Signature(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		description    string
		respStatus     int32
		errorMsg       string
		newPubKey      string
		validatorCount int
	}{
		{
			description:    "change public key: two validator",
			respStatus:     int32(shim.OK),
			newPubKey:      "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
			validatorCount: 2,
		},
		{
			description:    "change public key: two validator",
			respStatus:     int32(shim.OK),
			newPubKey:      "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
			validatorCount: 5,
		},
		{
			description:    "change public key: two validator",
			respStatus:     int32(shim.ERROR),
			errorMsg:       "the new key is equivalent to an existing one",
			newPubKey:      common.PubKey,
			validatorCount: 3,
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, _ := common.NewMockStub(t)

			ss, err := newSecrets(testCase.validatorCount)
			require.NoError(t, err)

			cfg := &proto.ACLConfig{
				AdminSKIEncoded: common.TestInitConfig.AdminSKIEncoded,
			}
			for _, s := range ss.pKeys() {
				cfg.Validators = append(cfg.Validators, &proto.ACLValidator{
					PublicKey: s,
					KeyType:   common.KeyTypeEd25519,
				})
			}
			cfgBytes, err := protojson.Marshal(cfg)
			require.NoError(t, err)

			nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
			reasonID := "1"
			mArgs := []string{common.FnChangePublicKeyWithBase58Signature, "", "acl", "acl", common.TestAddr, common.DefaultReason, reasonID, testCase.newPubKey, nonce}
			mArgs = append(mArgs, ss.pKeys()...)
			message := sha3.Sum256([]byte(strings.Join(mArgs, "")))
			err = ss.signs(message[:])
			require.NoError(t, err)
			mArgs = append(mArgs, ss.getSigns()...)

			keyPk, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{common.TestAddr})
			require.NoError(t, err)
			keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{common.TestAddrHashInHex})
			require.NoError(t, err)
			keyNonce, err := shim.CreateCompositeKey(compositekey.NoncePrefix, []string{common.TestAddr})
			require.NoError(t, err)

			hashed := sha3.Sum256(base58.Decode(common.PubKey))
			signAddr, err := pbBuf.Marshal(&pb.SignedAddress{
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
			mockStub.GetFunctionAndParametersReturns(common.FnChangePublicKeyWithBase58Signature, mArgs[1:])
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
			err = pbBuf.Unmarshal(val, signAddrGet)
			require.NoError(t, err)
			ssTx := []string{
				common.FnChangePublicKeyWithBase58Signature,
				"",
				"acl",
				"acl",
				common.TestAddr,
				common.DefaultReason,
			}
			ssTx = append(ssTx, ss.pKeys()...)
			ssTx = append(ssTx, ss.getSigns()...)
			require.True(t, pbBuf.Equal(&pb.SignedAddress{
				Address: &pb.Address{
					UserID:       "testUserID",
					Address:      hashed[:],
					IsIndustrial: true,
				},
				SignedTx: ssTx,
				Reason:   common.DefaultReason,
				ReasonId: int32(1),
			}, signAddrGet))
		})
	}
}

type artifact struct {
	private string
	public  string
	sign    string
}

type secrets struct {
	data []artifact
}

func (ss *secrets) pKeys() []string {
	pubKeys := make([]string, len(ss.data))

	for i := range ss.data {
		pubKeys[i] = ss.data[i].public
	}

	return pubKeys
}

func (ss *secrets) getSigns() []string {
	signs := make([]string, len(ss.data))

	for i := range ss.data {
		signs[i] = ss.data[i].sign
	}

	return signs
}

func newSecrets(validators int) (ss *secrets, err error) {
	ss = &secrets{}

	for i := 0; i < validators; i++ {
		public, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		ss.data = append(ss.data, artifact{
			private: base58.Encode(secret),
			public:  base58.Encode(public),
		})
	}

	return ss, nil
}

func (ss *secrets) signs(message []byte) error {
	for i := range ss.data {
		sign := ed25519.Sign(base58.Decode(ss.data[i].private), message)
		ss.data[i].sign = base58.Encode(sign)
		if !ed25519.Verify(base58.Decode(ss.data[i].public), message, sign) {
			return fmt.Errorf("invalid signature")
		}
	}
	return nil
}
