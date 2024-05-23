package unit

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/tests/common"
	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type tChangePublicKeyWithBase58Signature struct {
	newPubKey  string
	respStatus int32
}

func TestChangePublicKeyWithBase58Signature(t *testing.T) {
	t.Parallel()

	s := &tChangePublicKeyWithBase58Signature{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		respStatus: int32(shim.OK),
	}

	t.Run("change public key: two validator", func(t *testing.T) {
		changePublicKeyWithBase58Signature(t, s, 2)
	})

	t.Run("change public key: five validator", func(t *testing.T) {
		changePublicKeyWithBase58Signature(t, s, 5)
	})

	s = &tChangePublicKeyWithBase58Signature{
		newPubKey:  "aGGiDES6PZsZYz2ncsEXz8mXPxZRhVzMbgJFNAA7EA8",
		respStatus: int32(shim.ERROR),
	}

	t.Run("already exists public key with 3 validators", func(t *testing.T) {
		changePublicKeyWithBase58Signature(t, s, 3)
	})
}

func changePublicKeyWithBase58Signature(t *testing.T, ser *tChangePublicKeyWithBase58Signature, validatorCount int) {
	stub := shimtest.NewMockStub("mockStub", cc.New())
	require.NotNil(t, stub)
	cert, err := common.GetCert(common.AdminCertPath)
	require.NoError(t, err)
	err = common.SetCreator(stub, common.TestCreatorMSP, cert.Raw)
	require.NoError(t, err)

	ss, err := newSecrets(validatorCount)
	require.NoError(t, err)

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	reasonID := "1"
	mArgs := []string{"changePublicKeyWithBase58Signature", "", "acl", "", common.TestAddr, common.DefaultReason, reasonID, ser.newPubKey, nonce}
	message := sha3.Sum256([]byte(strings.Join(append(mArgs, ss.pKeys()...), "")))
	err = ss.signs(message[:])
	require.NoError(t, err)

	initArgs := [][]byte{
		common.TestAdminSKI,
		[]byte(strconv.Itoa(len(ss.pKeys()))),
	}
	var invokeArgs [][]byte

	for _, arg := range mArgs {
		invokeArgs = append(invokeArgs, []byte(arg))
	}
	for i := range ss.data {
		invokeArgs = append(invokeArgs, []byte(ss.data[i].public))
		initArgs = append(initArgs, []byte(ss.data[i].public))
	}
	for i := range ss.data {
		invokeArgs = append(invokeArgs, []byte(ss.data[i].sign))
	}

	stub.MockInit("0", initArgs)

	resp := stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
	)
	require.Equal(t, int32(shim.OK), resp.Status)

	respNewKey := stub.MockInvoke("0", invokeArgs)
	require.Equal(t, ser.respStatus, respNewKey.Status)
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
