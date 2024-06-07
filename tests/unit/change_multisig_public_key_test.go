package unit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

const newPubKey = "94EdE9iZRzU9mUiVDNxYKKWymHeBxHR8mA8AetFrg8m4"

type seriesChangeMultisigPublicKey struct {
	newPubKey  string
	kycHash    string
	testUserID string
	respStatus int32
	errorMsg   string
}

// add dynamic errorMsg in series
func (s *seriesChangeMultisigPublicKey) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestChangeMultisigPublicKeyEqual43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangeMultisigPublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		respStatus: int32(shim.OK),
		kycHash:    "kycHash",
		testUserID: "testUserID",
		errorMsg:   "",
	}

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyEqual44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangeMultisigPublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		respStatus: int32(shim.OK),
		kycHash:    "kycHash",
		testUserID: "testUserID",
		errorMsg:   "",
	}

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyEmpty(t *testing.T) {
	t.Parallel()

	s := &seriesChangeMultisigPublicKey{
		newPubKey:  "",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
		errorMsg:   errs.ErrEmptyNewKey,
	}

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangeMultisigPublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
	}

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d'",
		s.newPubKey,
		33,
	)
	s.SetError(errorMsg)

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangeMultisigPublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
	}

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d'",
		s.newPubKey,
		31,
	)
	s.SetError(errorMsg)

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &seriesChangeMultisigPublicKey{
		newPubKey:  "00000000000000000000000000000000",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
	}

	errorMsg := "failed base58 decoding of key " + s.newPubKey
	s.SetError(errorMsg)

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyWithSpecialSymbols(t *testing.T) {
	t.Parallel()

	s := &seriesChangeMultisigPublicKey{
		newPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
	}

	errorMsg := "failed base58 decoding of key " + s.newPubKey
	s.SetError(errorMsg)

	changeMultisigPublicKey(t, s)
}

func changeMultisigPublicKey(t *testing.T, ser *seriesChangeMultisigPublicKey) {
	stub := common.StubCreateAndInit(t)

	pubKeys := make([]string, 0, len(common.TestUsers))
	privateKeys := make([]string, 0, len(common.TestUsers))

	// add multisig members first
	for _, user := range common.TestUsers {
		pubKeys = append(pubKeys, user.PublicKey)
		privateKeys = append(privateKeys, user.PrivateKey)
		resp := stub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnAddUser),
				[]byte(user.PublicKey),
				[]byte(kycHash),
				[]byte(testUserID),
				[]byte(stateTrue),
			},
		)
		require.Equal(t, int32(shim.OK), resp.Status)
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	pubKeysBytes := make([][]byte, 0, len(pubKeys))
	for _, pubKey := range pubKeys {
		pubKeysBytes = append(pubKeysBytes, []byte(pubKey))
	}

	messageAddMultisig := sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisig, "3", nonce}, pubKeys...), "")))

	signaturesAddMultisig := make([][]byte, 0, len(privateKeys))
	for _, privateKey := range privateKeys {
		signaturesAddMultisig = append(
			signaturesAddMultisig,
			common.HexEncodedSignature(base58.Decode(privateKey), messageAddMultisig[:]),
		)
	}

	resp := stub.MockInvoke("0", append(append(
		append([][]byte{},
			[]byte(common.FnAddMultisig),
			[]byte("3"),
			[]byte(nonce)),
		pubKeysBytes...), signaturesAddMultisig...))
	require.Equal(t, int32(shim.OK), resp.Status)

	// derive address from hash of sorted base58-(DE)coded pubKeys
	pKeysString := strings.Join(pubKeys, "/")
	keysArrSorted, err := helpers.DecodeAndSort(pKeysString)
	require.NoError(t, err)
	hashedPksSortedOrder := sha3.Sum256(bytes.Join(keysArrSorted, []byte("")))
	addrEncoded := base58.CheckEncode(hashedPksSortedOrder[1:], hashedPksSortedOrder[0])

	valid := true
	newKey := ser.newPubKey
	// attempt to add a user if we use valid values in the seriesCheckKeys structure in test
	resp = stub.MockInvoke(
		"0",
		[][]byte{[]byte(common.FnAddUser), []byte(newKey), []byte(ser.kycHash), []byte(ser.testUserID), []byte(stateTrue)},
	)
	// if not, we substitute default valid values
	if resp.Status != int32(shim.OK) {
		valid = false
		resp = stub.MockInvoke(
			"0",
			[][]byte{[]byte(common.FnAddUser), []byte(newPubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
	}
	// then check that the user has been added
	require.Equal(t, int32(shim.OK), resp.Status)

	oldKey := pubKeys[0]
	var newPubKeys []string
	for i, pk := range pubKeys {
		if i == 0 {
			newPubKeys = append(newPubKeys, newKey)
		} else {
			newPubKeys = append(newPubKeys, pk)
		}
	}
	newSeparatedPubKeys := strings.Join(newPubKeys, "/")

	validatorPublicKeys := make([]string, len(common.TestUsersDifferentKeyTypes))
	for i, validator := range common.TestUsersDifferentKeyTypes {
		validatorPublicKeys[i] = validator.PublicKey
	}

	newNonce := strconv.Itoa(int(time.Now().Unix()*1000 + 1))
	reason := common.DefaultReason
	reasonID := "1"
	message := sha3.Sum256([]byte(strings.Join(append([]string{"changeMultisigPublicKey", addrEncoded, oldKey, newSeparatedPubKeys, reason, reasonID, newNonce}, validatorPublicKeys...), "")))

	validatorPublicKeysBytes := make([][]byte, len(common.TestUsersDifferentKeyTypes))
	signatures := make([][]byte, len(common.TestUsersDifferentKeyTypes))
	for i, validator := range common.TestUsersDifferentKeyTypes {
		validatorPublicKeysBytes[i] = []byte(validator.PublicKey)
		signatures[i] = common.HexEncodedSignature(base58.Decode(validator.PrivateKey), message[:])
	}

	// change key
	changeResponse := stub.MockInvoke("0", append(
		append([][]byte{[]byte("changeMultisigPublicKey"), []byte(addrEncoded), []byte(oldKey), []byte(newKey), []byte(reason), []byte(reasonID), []byte(newNonce)}, validatorPublicKeysBytes...), signatures...))
	require.Equal(t, ser.respStatus, changeResponse.Status)

	if !valid {
		require.Equal(t, ser.errorMsg, changeResponse.Message)
	}

	if valid {
		// check pb.SignedAddress
		result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(newSeparatedPubKeys)})
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AclResponse{}
		require.NoError(t, proto.Unmarshal(result.Payload, response))
		require.NotNil(t, response.Address)
		require.Equal(t, addrEncoded, response.Address.Address.AddrString(),
			"failed to find address %s by new key %s", addrEncoded, base58.Encode(hashedPksSortedOrder[:]))
		require.Equal(t, false, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
		require.Equal(t, true, response.Address.Address.IsMultisig, "invalid IsMultisig field")
		require.Equal(t, reason, response.Address.Reason)
		require.Equal(t, int32(1), response.Address.ReasonId)

		// check signatures of validators
		srcArgs := response.Address.SignaturePolicy.ReplaceKeysSignedTx[0:7]
		pksAndSignatures := response.Address.SignaturePolicy.ReplaceKeysSignedTx[7:]
		pksOfValidators := pksAndSignatures[:len(pksAndSignatures)/2]
		decodedMessage := sha3.Sum256([]byte(strings.Join(append(srcArgs, pksOfValidators...), "")))
		signaturesOfValidators := pksAndSignatures[len(pksAndSignatures)/2:]

		for i, vpk := range pksOfValidators {
			require.True(t, helpers.IsValidator(common.TestInitConfig.Validators, vpk), "pk %s does not belong to any validator", vpk)
			decodedSignature, err := hex.DecodeString(signaturesOfValidators[i])
			require.NoError(t, err)
			require.True(t, common.VerifySignature(base58.Decode(vpk), decodedMessage[:], decodedSignature),
				"the signature %s does not match the public key %s", signaturesOfValidators[i], vpk)
		}

		// check key replaced in pb.SignaturePolicy.PubKeys
		require.Equal(t, newKey, base58.Encode(response.Address.SignaturePolicy.PubKeys[0]), "pk is not replaced")
	}
}
