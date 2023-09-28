package cc

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/atomyze-foundation/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

type serieAddMultisigWithBase58Signature struct {
	testPubKey string
	errorMsg   string
}

// add dinamyc errorMsg in serie
func (s *serieAddMultisigWithBase58Signature) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestAddMultisigWithBase58SignaturePubkeyEqual43Symbols(t *testing.T) {
	t.Parallel()
	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		errorMsg:   errorMsgNotRecords,
	}

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubkeyEqual44Symbols(t *testing.T) {
	t.Parallel()
	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		errorMsg:   errorMsgNotRecords,
	}

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubkeyEmpty(t *testing.T) {
	t.Parallel()
	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "",
		errorMsg:   "encoded base 58 public key is empty",
	}

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubkeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.testPubKey + "'. decoded public key len is 33 but expected 32"
	s.SetError(errorMsg)

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubkeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.testPubKey + "'. decoded public key len is 31 but expected 32"
	s.SetError(errorMsg)

	AddMultisigWithBase58Signature(t, s)
}

// should be false, but true
func TestAddMultisigWithBase58SignaturePubkeyWrongString(t *testing.T) {
	t.Parallel()

	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "AbracadabraAbracadabraAbracadabraAbracadabra",
		errorMsg:   errorMsgNotRecords,
	}

	AddMultisigWithBase58Signature(t, s)
}

// should be false, but true (32 Symbols for numericc)
func TestAddMultisigWithBase58SignaturePubkeyWrongNumeric(t *testing.T) {
	t.Parallel()

	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "11111111111111111111111111111111",
		errorMsg:   errorMsgNotRecords,
	}

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubkeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "00000000000000000000000000000000",
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubkeyWithSpesialSymbols(t *testing.T) {
	t.Parallel()

	s := &serieAddMultisigWithBase58Signature{
		testPubKey: "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	AddMultisigWithBase58Signature(t, s)
}

func AddMultisigWithBase58Signature(t *testing.T, ser *serieAddMultisigWithBase58Signature) {
	stub := StubCreate(t)

	pubKeys := make([]string, 0, len(MockValidatorsKeys))
	privKeys := make([]string, 0, len(MockValidatorsKeys))
	for pubkey, privKey := range MockValidatorsKeys {
		pubKeys = append(pubKeys, pubkey)
		privKeys = append(privKeys, privKey)
	}

	// add multisig members first
	for _, memberPk := range pubKeys {
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(fnAddUser), []byte(memberPk), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
		assert.Equal(t, int32(shim.OK), resp.Status)
	}

	pubKeys[1] = ser.testPubKey

	pubKeysBytes := make([][]byte, 0, len(pubKeys))
	// duplicatePubKeys := make([]string, 0, len(pubKeys))
	duplicatePubKeysBytes := make([][]byte, 0, len(pubKeys))
	for i, pubkey := range pubKeys {
		pubKeysBytes = append(pubKeysBytes, []byte(pubkey))
		if i == 2 {
			// duplicatePubKeys = append(duplicatePubKeys, pubKeys[i-1])
			duplicatePubKeysBytes = append(duplicatePubKeysBytes, []byte(pubKeys[i-1])) //nolint:staticcheck
		} else {
			// duplicatePubKeys = append(duplicatePubKeys, pubkey)
			duplicatePubKeysBytes = append(duplicatePubKeysBytes, []byte(pubkey)) //nolint:staticcheck
		}
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	nonceForCaseWithDuplicates := strconv.Itoa(int(time.Now().Unix() * 1000))
	message := sha3.Sum256([]byte(strings.Join(append([]string{fnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonce}, pubKeys...), "")))
	messageForCaseWithDuplicates := sha3.Sum256([]byte(strings.Join(
		append([]string{fnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonceForCaseWithDuplicates}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privKeys))
	// duplicateSignatures      []string
	duplicateSignaturesBytes := make([][]byte, 0, len(privKeys))
	for i, privkey := range privKeys {
		signatures = append(signatures, []byte(base58.Encode(ed25519.Sign(base58.Decode(privkey), message[:]))))
		if i == 2 {
			// duplicateSignatures = append(duplicateSignatures, base58.Encode(ed25519.Sign(base58.Decode(privKeys[i-1]), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append( //nolint:staticcheck
				duplicateSignaturesBytes,
				[]byte(base58.Encode(ed25519.Sign(base58.Decode(privKeys[i-1]), messageForCaseWithDuplicates[:]))),
			)
		} else {
			// duplicateSignatures = append(duplicateSignatures, base58.Encode(ed25519.Sign(base58.Decode(privkey), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append( //nolint:staticcheck
				duplicateSignaturesBytes,
				[]byte(base58.Encode(ed25519.Sign(base58.Decode(privkey), messageForCaseWithDuplicates[:]))),
			)
		}
	}

	resp := stub.MockInvoke(
		"0",
		append(append(
			append([][]byte{},
				[]byte(fnAddMultisigWithBase58Signature),
				[]byte("req"), []byte("acl"), []byte("acl"),
				[]byte("3"),
				[]byte(nonce)),
			pubKeysBytes...,
		), signatures...),
	)
	assert.Equal(t, int32(shim.ERROR), resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)
}

func TestAddMultisigWithBase58Signature(t *testing.T) {
	stub := shimtest.NewMockStub("mockStub", New())
	stub.ChannelID = "acl"
	assert.NotNil(t, stub)
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	err = SetCreator(stub, testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	stub.MockInit("0", testInitArgs)

	pubKeys := make([]string, 0, len(MockValidatorsKeys))
	privKeys := make([]string, 0, len(MockValidatorsKeys))
	for pubkey, privKey := range MockValidatorsKeys {
		pubKeys = append(pubKeys, pubkey)
		privKeys = append(privKeys, privKey)
	}

	// add multisig members first
	for _, memberPk := range pubKeys {
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(fnAddUser), []byte(memberPk), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
		assert.Equal(t, int32(shim.OK), resp.Status)
	}

	pubKeysBytes := make([][]byte, 0, len(pubKeys))
	// duplicatePubKeys := make([]string, 0, len(pubKeys))
	duplicatePubKeysBytes := make([][]byte, 0, len(pubKeys))
	for i, pubkey := range pubKeys {
		pubKeysBytes = append(pubKeysBytes, []byte(pubkey))
		if i == 2 {
			// duplicatePubKeys = append(duplicatePubKeys, pubKeys[i-1])
			duplicatePubKeysBytes = append(duplicatePubKeysBytes, []byte(pubKeys[i-1]))
		} else {
			// duplicatePubKeys = append(duplicatePubKeys, pubkey)
			duplicatePubKeysBytes = append(duplicatePubKeysBytes, []byte(pubkey))
		}
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	nonceForCaseWithDuplicates := strconv.Itoa(int(time.Now().Unix() * 1000))
	message := sha3.Sum256([]byte(strings.Join(append([]string{fnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonce}, pubKeys...), "")))
	messageForCaseWithDuplicates := sha3.Sum256([]byte(strings.Join(
		append([]string{fnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonceForCaseWithDuplicates}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privKeys))
	// duplicateSignatures      []string
	duplicateSignaturesBytes := make([][]byte, 0, len(privKeys))
	for i, privkey := range privKeys {
		signatures = append(signatures, []byte(base58.Encode(ed25519.Sign(base58.Decode(privkey), message[:]))))
		if i == 2 {
			// duplicateSignatures = append(duplicateSignatures, base58.Encode(ed25519.Sign(base58.Decode(privKeys[i-1]), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append(
				duplicateSignaturesBytes,
				[]byte(base58.Encode(ed25519.Sign(base58.Decode(privKeys[i-1]), messageForCaseWithDuplicates[:]))),
			)
		} else {
			// duplicateSignatures = append(duplicateSignatures, base58.Encode(ed25519.Sign(base58.Decode(privkey), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append(
				duplicateSignaturesBytes,
				[]byte(base58.Encode(ed25519.Sign(base58.Decode(privkey), messageForCaseWithDuplicates[:]))),
			)
		}
	}

	t.Run("happy path", func(t *testing.T) {
		resp := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{},
					[]byte(fnAddMultisigWithBase58Signature),
					[]byte("req"), []byte("acl"), []byte("acl"),
					[]byte("3"),
					[]byte(nonce)),
				pubKeysBytes...,
			), signatures...),
		)
		assert.Equal(t, int32(shim.OK), resp.Status)

		// derive address from hash of sorted base58-(DE)coded pubKeys
		pkeysString := strings.Join(pubKeys, "/")
		keysArrSorted, err := DecodeAndSort(pkeysString)
		assert.NoError(t, err)
		hashedPksSortedOrder := sha3.Sum256(bytes.Join(keysArrSorted, []byte("")))
		addrEncoded := base58.CheckEncode(hashedPksSortedOrder[1:], hashedPksSortedOrder[0])

		// check pb.Address
		result := stub.MockInvoke("0", [][]byte{[]byte(fnCheckKeys), []byte(pkeysString)})
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AclResponse{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.Address)
		assert.Equal(t, hashedPksSortedOrder[:], response.Address.Address.Address, "failed to find address %s", addrEncoded)
		assert.Equal(t, true, response.Address.Address.IsMultisig)
		assert.Equal(t, false, response.Address.Address.IsIndustrial)
		assert.Equal(t, "", response.Address.Address.UserID, "UserID should be empty string for multisig")
		// check signatures confirming the agreement of all participants with the signature policy
		srcArgs := response.Address.SignedTx[0:6]
		pksAndSignatures := response.Address.SignedTx[6:]
		pksOfMultisigWallet := pksAndSignatures[:len(pksAndSignatures)/2]
		decodedMessage := sha3.Sum256([]byte(strings.Join(append(srcArgs, pksOfMultisigWallet...), "")))
		signaturesOfMembers := pksAndSignatures[len(pksAndSignatures)/2:]

		for i, pk := range pksOfMultisigWallet {
			decodedSignature := base58.Decode(signaturesOfMembers[i])
			assert.True(t, ed25519.Verify(base58.Decode(pk), decodedMessage[:], decodedSignature), "the signature %s does not match the public key %s", signaturesOfMembers[i], pk)
		}
	})

	t.Run("fraud: duplicate signature of multisig member (wrong case)", func(t *testing.T) {
		resp := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{}, []byte(fnAddMultisigWithBase58Signature), []byte("req"), []byte("acl"), []byte("acl"), []byte("3"),
					[]byte(nonceForCaseWithDuplicates)),
				duplicatePubKeysBytes...,
			), duplicateSignaturesBytes...),
		)
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.True(t, strings.Contains(resp.Message, "duplicated public keys"))
	})

	t.Run("not all members signed (wrong case)", func(t *testing.T) {
		resp := stub.MockInvoke("0", append(append(
			append([][]byte{},
				[]byte(fnAddMultisigWithBase58Signature),
				[]byte("req"), []byte("acl"), []byte("acl"),
				[]byte("3"),
				[]byte(nonce)),
			pubKeysBytes...), signatures[1:]...))
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.Equal(t, "the number of signatures (3) does not match the number of public keys (2)", resp.Message)
	})

	t.Run("with one fake signature (wrong case)", func(t *testing.T) {
		nonce = strconv.Itoa(int(time.Now().Unix()*1000 + 1))
		message = sha3.Sum256([]byte(strings.Join(append([]string{fnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonce}, pubKeys...), "")))

		signatures = signatures[:0]
		for i, privkey := range privKeys {
			if i < 2 {
				signatures = append(signatures, []byte(base58.Encode(ed25519.Sign(base58.Decode(privkey), message[:]))))
			} else {
				// make last signa wrong way
				hash := sha3.Sum256([]byte(strings.Join(append([]string{"lalalala", "req", "acl", "acl", "3", nonce}, pubKeys...), "")))
				signatures = append(signatures, []byte(base58.Encode(ed25519.Sign(base58.Decode(privkey), hash[:]))))
			}
		}

		// check
		resp := stub.MockInvoke(
			"0",
			append(
				append(
					append([][]byte{},
						[]byte(fnAddMultisigWithBase58Signature),
						[]byte("req"), []byte("acl"), []byte("acl"),
						[]byte("3"),
						[]byte(nonce)),
					pubKeysBytes...,
				),
				signatures...,
			),
		)
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.Equal(t, fmt.Sprintf("the signature %s does not match the public key %s",
			string(signatures[2]), pubKeys[2]), resp.Message)
	})
}
