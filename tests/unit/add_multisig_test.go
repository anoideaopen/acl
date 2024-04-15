package unit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/tests/common"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

type seriesAddMultisig struct {
	testPubKey string
	errorMsg   string
}

// add dynamic errorMsg in serie
func (s *seriesAddMultisig) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestAddMultisigPubkeyEqual43Symbols(t *testing.T) {
	t.Parallel()
	s := &seriesAddMultisig{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		errorMsg:   errs.ErrRecordsNotFound,
	}

	addMultisig(t, s)
}

func TestAddMultisigPubkeyEqual44Symbols(t *testing.T) {
	t.Parallel()
	s := &seriesAddMultisig{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		errorMsg:   errs.ErrRecordsNotFound,
	}

	addMultisig(t, s)
}

func TestAddMultisigPubkeyEmpty(t *testing.T) {
	t.Parallel()
	s := &seriesAddMultisig{
		testPubKey: "",
		errorMsg:   "encoded base 58 public key is empty",
	}

	addMultisig(t, s)
}

func TestAddMultisigPubkeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisig{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.testPubKey + "'. decoded public key len is 33 but expected 32"
	s.SetError(errorMsg)

	addMultisig(t, s)
}

func TestAddMultisigPubkeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisig{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
	}

	errorMsg := "incorrect decoded from base58 public key len '" +
		s.testPubKey + "'. decoded public key len is 31 but expected 32"
	s.SetError(errorMsg)

	addMultisig(t, s)
}

func TestAddMultisigPubkeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisig{
		testPubKey: "00000000000000000000000000000000",
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	addMultisig(t, s)
}

func TestAddMultisigPubkeyWithSpesialSymbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisig{
		testPubKey: "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	addMultisig(t, s)
}

func addMultisig(t *testing.T, ser *seriesAddMultisig) {
	stub := common.StubCreateAndInit(t)

	pubKeys := make([]string, 0, len(common.MockValidatorKeys))
	privKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubkey, privKey := range common.MockValidatorKeys {
		pubKeys = append(pubKeys, pubkey)
		privKeys = append(privKeys, privKey)
	}

	// add multisig members first
	for _, memberPk := range pubKeys {
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(common.FnAddUser), []byte(memberPk), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
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
	message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisig, "3", nonce}, pubKeys...), "")))
	messageForCaseWithDuplicates := sha3.Sum256([]byte(strings.Join(
		append([]string{common.FnAddMultisig, "3", nonceForCaseWithDuplicates}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privKeys))
	// duplicateSignatures      []string
	duplicateSignaturesBytes := make([][]byte, 0, len(privKeys))
	for i, privkey := range privKeys {
		signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), message[:]))))
		if i == 2 {
			// duplicateSignatures = append(duplicateSignatures, hex.EncodeToString(ed25519.Sign(base58.Decode(privKeys[i-1]), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append( //nolint:staticcheck
				duplicateSignaturesBytes,
				[]byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privKeys[i-1]), messageForCaseWithDuplicates[:]))),
			)
		} else {
			// duplicateSignatures = append(duplicateSignatures, hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append( //nolint:staticcheck
				duplicateSignaturesBytes,
				[]byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), messageForCaseWithDuplicates[:]))),
			)
		}
	}

	resp := stub.MockInvoke(
		"0",
		append(append(
			append([][]byte{},
				[]byte(common.FnAddMultisig),
				[]byte("3"),
				[]byte(nonce)),
			pubKeysBytes...,
		), signatures...),
	)
	assert.Equal(t, int32(shim.ERROR), resp.Status)
	assert.Equal(t, ser.errorMsg, resp.Message)
}

func TestAddMultisig(t *testing.T) {
	stub := common.StubCreateAndInit(t)

	pubKeys := make([]string, 0, len(common.MockValidatorKeys))
	privKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubkey, privKey := range common.MockValidatorKeys {
		pubKeys = append(pubKeys, pubkey)
		privKeys = append(privKeys, privKey)
	}

	// add multisig members first
	for _, memberPk := range pubKeys {
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(common.FnAddUser), []byte(memberPk), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
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
	message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisig, "3", nonce}, pubKeys...), "")))
	messageForCaseWithDuplicates := sha3.Sum256([]byte(strings.Join(
		append([]string{common.FnAddMultisig, "3", nonceForCaseWithDuplicates}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privKeys))
	// duplicateSignatures      []string
	duplicateSignaturesBytes := make([][]byte, 0, len(privKeys))
	for i, privkey := range privKeys {
		signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), message[:]))))
		if i == 2 {
			// duplicateSignatures = append(duplicateSignatures, hex.EncodeToString(ed25519.Sign(base58.Decode(privKeys[i-1]), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append(
				duplicateSignaturesBytes,
				[]byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privKeys[i-1]), messageForCaseWithDuplicates[:]))),
			)
		} else {
			// duplicateSignatures = append(duplicateSignatures, hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append(
				duplicateSignaturesBytes,
				[]byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), messageForCaseWithDuplicates[:]))),
			)
		}
	}

	t.Run("happy path", func(t *testing.T) {
		resp := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{},
					[]byte(common.FnAddMultisig),
					[]byte("3"),
					[]byte(nonce)),
				pubKeysBytes...,
			), signatures...),
		)
		assert.Equal(t, int32(shim.OK), resp.Status)

		// derive address from hash of sorted base58-(DE)coded pubKeys
		pkeysString := strings.Join(pubKeys, "/")
		keysArrSorted, err := helpers.DecodeAndSort(pkeysString)
		assert.NoError(t, err)
		hashedPksSortedOrder := sha3.Sum256(bytes.Join(keysArrSorted, []byte("")))
		addrEncoded := base58.CheckEncode(hashedPksSortedOrder[1:], hashedPksSortedOrder[0])

		// check pb.Address
		result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(pkeysString)})
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AclResponse{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.Address)
		assert.Equal(t, hashedPksSortedOrder[:], response.Address.Address.Address, "failed to find address %s", addrEncoded)
		assert.Equal(t, true, response.Address.Address.IsMultisig)
		assert.Equal(t, false, response.Address.Address.IsIndustrial)
		assert.Equal(t, "", response.Address.Address.UserID, "UserID should be empty string for multisig")
		// check signatures confirming the agreement of all participants with the signature policy
		srcArgs := response.Address.SignedTx[0:3]
		pksAndSignatures := response.Address.SignedTx[3:]
		pksOfMultisigWallet := pksAndSignatures[:len(pksAndSignatures)/2]
		decodedMessage := sha3.Sum256([]byte(strings.Join(append(srcArgs, pksOfMultisigWallet...), "")))
		signaturesOfMembers := pksAndSignatures[len(pksAndSignatures)/2:]

		for i, pk := range pksOfMultisigWallet {
			decodedSignature, err := hex.DecodeString(signaturesOfMembers[i])
			assert.NoError(t, err)
			assert.True(t, ed25519.Verify(base58.Decode(pk), decodedMessage[:], decodedSignature), "the signature %s does not match the public key %s", signaturesOfMembers[i], pk)
		}
	})

	t.Run("fraud: duplicate signature of multisig member (wrong case)", func(t *testing.T) {
		resp := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{}, []byte(common.FnAddMultisig), []byte("3"),
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
				[]byte(common.FnAddMultisig),
				[]byte("3"),
				[]byte(nonce)),
			pubKeysBytes...), signatures[1:]...))
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.Equal(t, "the number of signatures (3) does not match the number of public keys (2)", resp.Message)
	})

	t.Run("with one fake signature (wrong case)", func(t *testing.T) {
		nonce = strconv.Itoa(int(time.Now().Unix()*1000 + 1))
		message = sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisig, "3", nonce}, pubKeys...), "")))

		signatures = signatures[:0]
		for i, privkey := range privKeys {
			if i < 2 {
				signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), message[:]))))
			} else {
				// make last signa wrong way
				hash := sha3.Sum256([]byte(strings.Join(append([]string{"lalalala", "3", nonce}, pubKeys...), "")))
				signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), hash[:]))))
			}
		}

		// check
		resp := stub.MockInvoke(
			"0",
			append(
				append(
					append([][]byte{},
						[]byte(common.FnAddMultisig),
						[]byte("3"),
						[]byte(nonce)),
					pubKeysBytes...,
				),
				signatures...,
			),
		)
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.Equal(t, fmt.Sprintf("the signature %s does not match the public key %s",
			string(signatures[2]), hex.EncodeToString(base58.Decode(pubKeys[2]))), resp.Message)
	})

	t.Run("wrong number of signature policy", func(t *testing.T) {
		n := "10"
		resp := stub.MockInvoke("0", append(append(
			append([][]byte{},
				[]byte(common.FnAddMultisig),
				[]byte(n),
				[]byte(nonce)),
			pubKeysBytes...), signatures...))
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.Equal(t, "N ("+n+") is greater then M (number of pubkeys, "+strconv.Itoa(len(pubKeys))+")", resp.Message)
	})

	t.Run("wrong number of parameters", func(t *testing.T) {
		s := make([][]byte, 0)
		p := make([][]byte, 0)
		resp := stub.MockInvoke("0", append(append(
			append([][]byte{},
				[]byte(common.FnAddMultisig),
				[]byte(nonce)),
			p...), s...))
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.Equal(t, "incorrect number of arguments: 1, but this method expects: address, N (signatures required), nonce, public keys, signatures", resp.Message)
	})
}

func TestNonce(t *testing.T) {
	stub := common.StubCreateAndInit(t)

	pubKeys := make([]string, 0, len(common.MockValidatorKeys))
	privKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubkey, privKey := range common.MockValidatorKeys {
		pubKeys = append(pubKeys, pubkey)
		privKeys = append(privKeys, privKey)
	}

	// add multisig members first
	for _, memberPk := range pubKeys {
		resp := stub.MockInvoke(
			"0",
			[][]byte{[]byte(common.FnAddUser), []byte(memberPk), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
		assert.Equal(t, int32(shim.OK), resp.Status)
	}

	pubKeysBytes := make([][]byte, 0, len(pubKeys))
	for _, pubkey := range pubKeys {
		pubKeysBytes = append(pubKeysBytes, []byte(pubkey))
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisig, "3", nonce}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privKeys))
	for _, privkey := range privKeys {
		signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), message[:]))))
	}
	t.Run("use duplicate nonce", func(t *testing.T) {
		nonceForDuplicateNonceTest := strconv.Itoa(int(time.Now().Unix() * 1000))
		resp := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{},
					[]byte(common.FnAddMultisig),
					[]byte("3"),
					[]byte(nonceForDuplicateNonceTest)),
				pubKeysBytes...,
			), signatures...),
		)
		assert.Equal(t, int32(shim.OK), resp.Status)

		resp2 := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{},
					[]byte(common.FnAddMultisig),
					[]byte("3"),
					[]byte(nonceForDuplicateNonceTest)),
				pubKeysBytes...,
			), signatures...),
		)
		assert.Equal(t, int32(shim.ERROR), resp2.Status)
		assert.Contains(t, resp2.Message, "incorrect nonce")
	})

	t.Run("nonce less than exists", func(t *testing.T) {
		n := strconv.Itoa(1)
		resp := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{},
					[]byte(common.FnAddMultisig),
					[]byte("3"),
					[]byte(n)),
				pubKeysBytes...,
			), signatures...),
		)
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.Contains(t, resp.Message, "less than exists")
	})
}
