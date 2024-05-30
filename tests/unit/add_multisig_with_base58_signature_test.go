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

type seriesAddMultisigWithBase58Signature struct {
	testPubKey string
	errorMsg   string
}

// add dynamic errorMsg in series
func (s *seriesAddMultisigWithBase58Signature) SetError(errMsg string) {
	s.errorMsg = errMsg
}

func TestAddMultisigWithBase58SignaturePubKeyEqual43Symbols(t *testing.T) {
	t.Parallel()
	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2",
		errorMsg:   errs.ErrRecordsNotFound,
	}

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubKeyEqual44Symbols(t *testing.T) {
	t.Parallel()
	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2z",
		errorMsg:   errs.ErrRecordsNotFound,
	}

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubKeyEmpty(t *testing.T) {
	t.Parallel()
	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "",
		errorMsg:   "empty public key detected",
	}

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubKeyMoreThan44Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR2zV",
	}

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d'",
		s.testPubKey,
		33,
	)
	s.SetError(errorMsg)

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubKeyLessThan43Symbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "Cv8S2Y7pDT74AUma95Fdy6ZUX5NBVTQR7WRbdq46VR",
	}

	errorMsg := fmt.Sprintf(
		"incorrect len of decoded from base58 public key '%s': '%d'",
		s.testPubKey,
		31,
	)
	s.SetError(errorMsg)

	AddMultisigWithBase58Signature(t, s)
}

// should be false, but true
func TestAddMultisigWithBase58SignaturePubKeyWrongString(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "AbracadabraAbracadabraAbracadabraAbracadabra",
		errorMsg:   errs.ErrRecordsNotFound,
	}

	AddMultisigWithBase58Signature(t, s)
}

// should be false, but true (32 Symbols for numeric)
func TestAddMultisigWithBase58SignaturePubKeyWrongNumeric(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "11111111111111111111111111111111",
		errorMsg:   errs.ErrRecordsNotFound,
	}

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubKeyWrongNumericZero(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "00000000000000000000000000000000",
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	AddMultisigWithBase58Signature(t, s)
}

func TestAddMultisigWithBase58SignaturePubKeyWithSpecialSymbols(t *testing.T) {
	t.Parallel()

	s := &seriesAddMultisigWithBase58Signature{
		testPubKey: "Abracadabra#$)*&@=+^%~AbracadabraAbracadabra",
	}

	errorMsg := "failed base58 decoding of key " + s.testPubKey
	s.SetError(errorMsg)

	AddMultisigWithBase58Signature(t, s)
}

func AddMultisigWithBase58Signature(t *testing.T, ser *seriesAddMultisigWithBase58Signature) {
	stub := common.StubCreateAndInit(t)

	pubKeys := make([]string, 0, len(common.MockValidatorKeys))
	privateKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubKey, privateKey := range common.MockValidatorKeys {
		pubKeys = append(pubKeys, pubKey)
		privateKeys = append(privateKeys, privateKey)
	}

	// add multisig members first
	for _, validator := range common.TestInitConfig.Validators {
		resp := stub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnAddUser),
				[]byte(validator.PublicKey),
				[]byte(kycHash),
				[]byte(testUserID),
				[]byte(stateTrue),
				[]byte(validator.KeyType),
			},
		)
		require.Equal(t, int32(shim.OK), resp.Status)
	}

	pubKeys[1] = ser.testPubKey

	pubKeysBytes := make([][]byte, 0, len(pubKeys))
	// duplicatePubKeys := make([]string, 0, len(pubKeys))
	duplicatePubKeysBytes := make([][]byte, 0, len(pubKeys))
	for i, pubKey := range pubKeys {
		pubKeysBytes = append(pubKeysBytes, []byte(pubKey))
		if i == 2 {
			// duplicatePubKeys = append(duplicatePubKeys, pubKeys[i-1])
			duplicatePubKeysBytes = append(duplicatePubKeysBytes, []byte(pubKeys[i-1])) //nolint:staticcheck
		} else {
			// duplicatePubKeys = append(duplicatePubKeys, pubKey)
			duplicatePubKeysBytes = append(duplicatePubKeysBytes, []byte(pubKey)) //nolint:staticcheck
		}
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	nonceForCaseWithDuplicates := strconv.Itoa(int(time.Now().Unix() * 1000))
	message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonce}, pubKeys...), "")))
	messageForCaseWithDuplicates := sha3.Sum256([]byte(strings.Join(
		append([]string{common.FnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonceForCaseWithDuplicates}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privateKeys))
	// duplicateSignatures      []string
	duplicateSignaturesBytes := make([][]byte, 0, len(privateKeys))
	for i, privateKey := range privateKeys {
		signatures = append(signatures, common.Base58EncodedSignature(base58.Decode(privateKey), message[:]))
		if i == 2 {
			// duplicateSignatures = append(duplicateSignatures, base58.Encode(ed25519.Sign(base58.Decode(privateKeys[i-1]), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append( //nolint:staticcheck
				duplicateSignaturesBytes,
				common.Base58EncodedSignature(base58.Decode(privateKeys[i-1]), messageForCaseWithDuplicates[:]),
			)
		} else {
			// duplicateSignatures = append(duplicateSignatures, base58.Encode(ed25519.Sign(base58.Decode(privateKey), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append( //nolint:staticcheck
				duplicateSignaturesBytes,
				common.Base58EncodedSignature(base58.Decode(privateKey), messageForCaseWithDuplicates[:]),
			)
		}
	}

	resp := stub.MockInvoke(
		"0",
		append(append(
			append([][]byte{},
				[]byte(common.FnAddMultisigWithBase58Signature),
				[]byte("req"), []byte("acl"), []byte("acl"),
				[]byte("3"),
				[]byte(nonce)),
			pubKeysBytes...,
		), signatures...),
	)
	require.Equal(t, int32(shim.ERROR), resp.Status)
	require.Contains(t, resp.Message, ser.errorMsg)
}

func TestAddMultisigWithBase58Signature(t *testing.T) {
	stub := common.StubCreateAndInit(t)

	pubKeys := make([]string, 0, len(common.MockValidatorKeys))
	privateKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubKey, privateKey := range common.MockValidatorKeys {
		pubKeys = append(pubKeys, pubKey)
		privateKeys = append(privateKeys, privateKey)
	}

	// add multisig members first
	for _, validator := range common.TestInitConfig.Validators {
		resp := stub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnAddUser),
				[]byte(validator.PublicKey),
				[]byte(kycHash),
				[]byte(testUserID),
				[]byte(stateTrue),
				[]byte(validator.KeyType),
			},
		)
		require.Equal(t, int32(shim.OK), resp.Status)
	}

	pubKeysBytes := make([][]byte, 0, len(pubKeys))
	// duplicatePubKeys := make([]string, 0, len(pubKeys))
	duplicatePubKeysBytes := make([][]byte, 0, len(pubKeys))
	for i, pubKey := range pubKeys {
		pubKeysBytes = append(pubKeysBytes, []byte(pubKey))
		if i == 2 {
			// duplicatePubKeys = append(duplicatePubKeys, pubKeys[i-1])
			duplicatePubKeysBytes = append(duplicatePubKeysBytes, []byte(pubKeys[i-1]))
		} else {
			// duplicatePubKeys = append(duplicatePubKeys, pubKey)
			duplicatePubKeysBytes = append(duplicatePubKeysBytes, []byte(pubKey))
		}
	}

	nonce := strconv.Itoa(int(time.Now().Unix() * 1000))
	nonceForCaseWithDuplicates := strconv.Itoa(int(time.Now().Unix() * 1000))
	message := sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonce}, pubKeys...), "")))
	messageForCaseWithDuplicates := sha3.Sum256([]byte(strings.Join(
		append([]string{common.FnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonceForCaseWithDuplicates}, pubKeys...), "")))

	signatures := make([][]byte, 0, len(privateKeys))
	// duplicateSignatures      []string
	duplicateSignaturesBytes := make([][]byte, 0, len(privateKeys))
	for i, privateKey := range privateKeys {
		signatures = append(signatures, common.Base58EncodedSignature(base58.Decode(privateKey), message[:]))
		if i == 2 {
			// duplicateSignatures = append(duplicateSignatures, base58.Encode(ed25519.Sign(base58.Decode(privateKeys[i-1]), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append(
				duplicateSignaturesBytes,
				common.Base58EncodedSignature(base58.Decode(privateKeys[i-1]), messageForCaseWithDuplicates[:]),
			)
		} else {
			// duplicateSignatures = append(duplicateSignatures, base58.Encode(ed25519.Sign(base58.Decode(privateKey), messageForCaseWithDuplicates[:])))
			duplicateSignaturesBytes = append(
				duplicateSignaturesBytes,
				common.Base58EncodedSignature(base58.Decode(privateKey), messageForCaseWithDuplicates[:]),
			)
		}
	}

	t.Run("happy path", func(t *testing.T) {
		resp := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{},
					[]byte(common.FnAddMultisigWithBase58Signature),
					[]byte("req"), []byte("acl"), []byte("acl"),
					[]byte("3"),
					[]byte(nonce)),
				pubKeysBytes...,
			), signatures...),
		)
		require.Equal(t, int32(shim.OK), resp.Status)

		// derive address from hash of sorted base58-(DE)coded pubKeys
		pKeysString := strings.Join(pubKeys, "/")
		keysArrSorted, err := helpers.DecodeAndSort(pKeysString)
		require.NoError(t, err)
		hashedPksSortedOrder := sha3.Sum256(bytes.Join(keysArrSorted, []byte("")))
		addrEncoded := base58.CheckEncode(hashedPksSortedOrder[1:], hashedPksSortedOrder[0])

		// check pb.Address
		result := stub.MockInvoke("0", [][]byte{[]byte(common.FnCheckKeys), []byte(pKeysString)})
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AclResponse{}
		require.NoError(t, proto.Unmarshal(result.Payload, response))
		require.NotNil(t, response.Address)
		require.Equal(t, hashedPksSortedOrder[:], response.Address.Address.Address, "failed to find address %s", addrEncoded)
		require.Equal(t, true, response.Address.Address.IsMultisig)
		require.Equal(t, false, response.Address.Address.IsIndustrial)
		require.Equal(t, "", response.Address.Address.UserID, "UserID should be empty string for multisig")
		// check signatures confirming the agreement of all participants with the signature policy
		srcArgs := response.Address.SignedTx[0:6]
		pksAndSignatures := response.Address.SignedTx[6:]
		pksOfMultisigWallet := pksAndSignatures[:len(pksAndSignatures)/2]
		decodedMessage := sha3.Sum256([]byte(strings.Join(append(srcArgs, pksOfMultisigWallet...), "")))
		signaturesOfMembers := pksAndSignatures[len(pksAndSignatures)/2:]

		for i, pk := range pksOfMultisigWallet {
			decodedSignature := base58.Decode(signaturesOfMembers[i])
			require.True(t, common.VerifySignature(base58.Decode(pk), decodedMessage[:], decodedSignature), "the signature %s does not match the public key %s", signaturesOfMembers[i], pk)
		}
	})

	t.Run("fraud: duplicate signature of multisig member (wrong case)", func(t *testing.T) {
		resp := stub.MockInvoke(
			"0",
			append(append(
				append([][]byte{}, []byte(common.FnAddMultisigWithBase58Signature), []byte("req"), []byte("acl"), []byte("acl"), []byte("3"),
					[]byte(nonceForCaseWithDuplicates)),
				duplicatePubKeysBytes...,
			), duplicateSignaturesBytes...),
		)
		require.Equal(t, int32(shim.ERROR), resp.Status)
		require.True(t, strings.Contains(resp.Message, "duplicated public keys"))
	})

	t.Run("not all members signed (wrong case)", func(t *testing.T) {
		resp := stub.MockInvoke("0", append(append(
			append([][]byte{},
				[]byte(common.FnAddMultisigWithBase58Signature),
				[]byte("req"), []byte("acl"), []byte("acl"),
				[]byte("3"),
				[]byte(nonce)),
			pubKeysBytes...), signatures[1:]...))
		require.Equal(t, int32(shim.ERROR), resp.Status)
		require.Contains(t, resp.Message, "counts of keys and signatures are not equal")
	})

	t.Run("with one fake signature (wrong case)", func(t *testing.T) {
		nonce = strconv.Itoa(int(time.Now().Unix()*1000 + 1))
		message = sha3.Sum256([]byte(strings.Join(append([]string{common.FnAddMultisigWithBase58Signature, "req", "acl", "acl", "3", nonce}, pubKeys...), "")))

		signatures = signatures[:0]
		for i, privateKey := range privateKeys {
			if i < 2 {
				signatures = append(signatures, common.Base58EncodedSignature(base58.Decode(privateKey), message[:]))
			} else {
				// make last signature wrong way
				hash := sha3.Sum256([]byte(strings.Join(append([]string{"lalalala", "req", "acl", "acl", "3", nonce}, pubKeys...), "")))
				signatures = append(signatures, common.Base58EncodedSignature(base58.Decode(privateKey), hash[:]))
			}
		}

		// check
		resp := stub.MockInvoke(
			"0",
			append(
				append(
					append([][]byte{},
						[]byte(common.FnAddMultisigWithBase58Signature),
						[]byte("req"), []byte("acl"), []byte("acl"),
						[]byte("3"),
						[]byte(nonce)),
					pubKeysBytes...,
				),
				signatures...,
			),
		)
		require.Equal(t, int32(shim.ERROR), resp.Status)
		require.Contains(t, resp.Message, fmt.Sprintf("the signature %s does not match the public key %s",
			hex.EncodeToString(base58.Decode(string(signatures[2]))), pubKeys[2]))
	})
}
