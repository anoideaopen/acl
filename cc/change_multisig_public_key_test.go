package cc

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

const newPubKey = "94EdE9iZRzU9mUiVDNxYKKWymHeBxHR8mA8AetFrg8m4"

type serieChangeMultisigPublicKey struct {
	newPubKey  string
	kycHash    string
	testUserID string
	respStatus int32
	errorMsg   string
}

// add dinamyc errorMsg in serie
func (s *serieChangeMultisigPublicKey) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestChangeMultisigPublicKeyEqual43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieChangeMultisigPublicKey{
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

	s := &serieChangeMultisigPublicKey{
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

	s := &serieChangeMultisigPublicKey{
		newPubKey:  "",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
		errorMsg:   errorMsgEmptyKey,
	}

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &serieChangeMultisigPublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.newPubKey + "'. decoded public key len is 33 but expected 32"
	s.SetError(errorMsg)

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieChangeMultisigPublicKey{
		newPubKey:  "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.newPubKey + "'. decoded public key len is 31 but expected 32"
	s.SetError(errorMsg)

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &serieChangeMultisigPublicKey{
		newPubKey:  "00000000000000000000000000000000",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
	}

	errorMsg := "failed base58 decoding of key " + s.newPubKey
	s.SetError(errorMsg)

	changeMultisigPublicKey(t, s)
}

func TestChangeMultisigPublicKeyWithSpesialSymbols(t *testing.T) {
	t.Parallel()

	s := &serieChangeMultisigPublicKey{
		newPubKey:  "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
		respStatus: int32(shim.ERROR),
		kycHash:    "kycHash",
		testUserID: "testUserID",
	}

	errorMsg := "failed base58 decoding of key " + s.newPubKey
	s.SetError(errorMsg)

	changeMultisigPublicKey(t, s)
}

func changeMultisigPublicKey(t *testing.T, ser *serieChangeMultisigPublicKey) {
	stub := shimtest.NewMockStub("mockStub", New())
	assert.NotNil(t, stub)
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	err = SetCreator(stub, testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	stub.MockInit("0", testInitArgs)

	pubKeys := make([]string, 0, len(MockValidatorKeys))
	privKeys := make([]string, 0, len(MockValidatorKeys))
	for pubKey, privKey := range MockValidatorKeys {
		pubKeys = append(pubKeys, pubKey)
		privKeys = append(privKeys, privKey)
	}

	// add multisig members first
	for _, memberPk := range pubKeys {
		resp := stub.MockInvoke("0", [][]byte{[]byte(fnAddUser), []byte(memberPk), []byte(kycHash), []byte(testUserID), []byte(stateTrue)})
		assert.Equal(t, int32(shim.OK), resp.Status)
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	pubKeysBytes := make([][]byte, 0, len(pubKeys))
	for _, pubKey := range pubKeys {
		pubKeysBytes = append(pubKeysBytes, []byte(pubKey))
	}

	messageAddMultisig := sha3.Sum256([]byte(strings.Join(append([]string{fnAddMultisig, "3", nonce}, pubKeys...), "")))

	signaturesAddMultisig := make([][]byte, 0, len(privKeys))
	for _, privKey := range privKeys {
		signaturesAddMultisig = append(
			signaturesAddMultisig,
			[]byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privKey), messageAddMultisig[:]))),
		)
	}

	resp := stub.MockInvoke("0", append(append(
		append([][]byte{},
			[]byte(fnAddMultisig),
			[]byte("3"),
			[]byte(nonce)),
		pubKeysBytes...), signaturesAddMultisig...))
	assert.Equal(t, int32(shim.OK), resp.Status)

	// derive address from hash of sorted base58-(DE)coded pubkeys
	pkeysString := strings.Join(pubKeys, "/")
	keysArrSorted, err := DecodeAndSort(pkeysString)
	assert.NoError(t, err)
	hashedPksSortedOrder := sha3.Sum256(bytes.Join(keysArrSorted, []byte("")))
	addrEncoded := base58.CheckEncode(hashedPksSortedOrder[1:], hashedPksSortedOrder[0])

	valid := true
	newKey := ser.newPubKey
	// attempt to add a user if we use valid values in the serieCheckKeys structure in test
	resp = stub.MockInvoke(
		"0",
		[][]byte{[]byte(fnAddUser), []byte(newKey), []byte(ser.kycHash), []byte(ser.testUserID), []byte(stateTrue)},
	)
	// if not, we substitute default valid values
	if resp.Status != int32(shim.OK) {
		valid = false
		resp = stub.MockInvoke(
			"0",
			[][]byte{[]byte(fnAddUser), []byte(newPubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
	}
	// then check that the user has been added
	assert.Equal(t, int32(shim.OK), resp.Status)

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

	newNonce := strconv.Itoa(int(time.Now().Unix()*1000 + 1))
	reason := "because..."
	reasonID := "1"
	message := sha3.Sum256([]byte(strings.Join(append([]string{"changeMultisigPublicKey", addrEncoded, oldKey, newSeparatedPubKeys, reason, reasonID, newNonce}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privKeys))
	for _, privkey := range privKeys {
		signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), message[:]))))
	}

	// change key
	changeResponse := stub.MockInvoke("0", append(
		append([][]byte{[]byte("changeMultisigPublicKey"), []byte(addrEncoded), []byte(oldKey), []byte(newKey), []byte(reason), []byte(reasonID), []byte(newNonce)}, pubKeysBytes...), signatures...))
	assert.Equal(t, ser.respStatus, changeResponse.Status)

	if !valid {
		assert.Equal(t, ser.errorMsg, changeResponse.Message)
	}

	if valid {
		// check pb.SignedAddress
		result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(newSeparatedPubKeys)})
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AclResponse{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.Address)
		assert.Equal(t, addrEncoded, response.Address.Address.AddrString(),
			"failed to find address %s by new key %s", addrEncoded, base58.Encode(hashedPksSortedOrder[:]))
		assert.Equal(t, false, response.Address.Address.IsIndustrial, "invalid isIndustrial field")
		assert.Equal(t, true, response.Address.Address.IsMultisig, "invalid IsMultisig field")
		assert.Equal(t, reason, response.Address.Reason)
		assert.Equal(t, int32(1), response.Address.ReasonId)

		// check signatures of validators
		srcArgs := response.Address.SignaturePolicy.ReplaceKeysSignedTx[0:7]
		pksAndSignatures := response.Address.SignaturePolicy.ReplaceKeysSignedTx[7:]
		pksOfValidators := pksAndSignatures[:len(pksAndSignatures)/2]
		decodedMessage := sha3.Sum256([]byte(strings.Join(append(srcArgs, pksOfValidators...), "")))
		signaturesOfValidators := pksAndSignatures[len(pksAndSignatures)/2:]

		mockValidatorsPublicKeys := make([]string, 0, len(MockValidatorKeys))
		for pubkey := range MockValidatorKeys {
			mockValidatorsPublicKeys = append(mockValidatorsPublicKeys, pubkey)
		}
		for i, vpk := range pksOfValidators {
			assert.True(t, IsValidator(mockValidatorsPublicKeys, vpk), "pk %s does not belong to any validator", vpk)
			decodedSignature, err := hex.DecodeString(signaturesOfValidators[i])
			assert.NoError(t, err)
			assert.True(t, ed25519.Verify(base58.Decode(vpk), decodedMessage[:], decodedSignature),
				"the signature %s does not match the public key %s", signaturesOfValidators[i], vpk)
		}

		// check key replaced in pb.SignaturePolicy.PubKeys
		assert.Equal(t, newKey, base58.Encode(response.Address.SignaturePolicy.PubKeys[0]), "pk is not replaced")
	}
}
