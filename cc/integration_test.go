package cc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/foundation/mock"
	mstub "github.com/anoideaopen/foundation/mock/stub"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/unit/fixtures_test"
	"github.com/anoideaopen/foundation/token"
	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	replaceTxChangePrefix = "replacetx"
	signedTxChangePrefix  = "signedtx"
)

var testValidators = [][]byte{
	[]byte("A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4"),
	[]byte("5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5"),
	[]byte("6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4"),
}

var testInitArgs = append(
	[][]byte{
		[]byte("dc752d6afb51c33327b7873fdb08adb91de15ee7c88f4f9949445aeeb8ea4e99"),
		[]byte(strconv.Itoa(len(testValidators))),
	},
	testValidators...)

func TestAclInitWrongAdminSkiFormat(t *testing.T) {
	aclCC := mstub.NewMockStub("acl", New())
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	aclCC.SetCreator(creator)

	response := aclCC.MockInit("0", [][]byte{[]byte("a"), []byte("0")})
	assert.NotNil(t, response)
	assert.Equal(t, int32(500), response.Status)
	assert.Equal(t, "invalid admin SKI (index of args 0) format found 'a' but expected hex encoded string", response.Message)
}

func TestAclInitWrongValidatorCountFormat(t *testing.T) {
	aclCC := mstub.NewMockStub("acl", New())
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	aclCC.SetCreator(creator)

	response := aclCC.MockInit("0", [][]byte{[]byte("dc752d6afb51c33327b7873fdb08adb91de15ee7c88f4f9949445aeeb8ea4e99"), []byte("a")})
	assert.NotNil(t, response)
	assert.Equal(t, int32(500), response.Status)
	assert.Equal(t, "invalid validator count (index of args 1) format found 'a' but expected value with type int", response.Message)
}

func TestAclInitZeroArgs(t *testing.T) {
	aclCC := mstub.NewMockStub("acl", New())
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	aclCC.SetCreator(creator)

	response := aclCC.MockInit("0", [][]byte{})
	assert.NotNil(t, response)
	assert.Equal(t, int32(500), response.Status)
	assert.Equal(t, "arguments should be at least 2", response.Message)
}

func TestAclInitTwoArgs(t *testing.T) {
	aclCC := mstub.NewMockStub("acl", New())
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	aclCC.SetCreator(creator)

	adminSkiArg := "dc752d6afb51c33327b7873fdb08adb91de15ee7c88f4f9949445aeeb8ea4e99"
	decodeString, err := hex.DecodeString(adminSkiArg)
	assert.NoError(t, err)
	testValidatorCount := "0"
	response := aclCC.MockInit("0", [][]byte{[]byte(adminSkiArg), []byte(testValidatorCount)})
	assert.NotNil(t, response)
	assert.Equal(t, int32(200), response.Status)
	assert.Empty(t, response.Message)

	stateInitArgs, err := GetInitArgsFromState(aclCC)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(stateInitArgs.Validators))
	assert.Equal(t, decodeString, stateInitArgs.AdminSKI)
	assert.Equal(t, int64(0), stateInitArgs.ValidatorsCount)
}

func TestAclInitArgs(t *testing.T) {
	aclCC := mstub.NewMockStub("acl", New())
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	aclCC.SetCreator(creator)

	response := aclCC.MockInit("0", testInitArgs)
	assert.NotNil(t, response)
	assert.Equal(t, int32(200), response.Status)
	assert.Empty(t, response.Message)

	stateInitArgs, err := GetInitArgsFromState(aclCC)
	assert.NoError(t, err)
	assert.Equal(t, len(testValidators), len(stateInitArgs.Validators))
}

func TestEmitTransfer(t *testing.T) {
	ledgerMock := mock.NewLedger(t)
	owner := ledgerMock.NewWallet()

	aclCC := mstub.NewMockStub("acl", New())
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	aclCC.SetCreator(creator)
	aclCC.MockInit("0", testInitArgs)
	ledgerMock.SetACL(aclCC)

	cfg := &pb.Config{
		Contract: &pb.ContractConfig{
			Symbol:   "FIAT",
			RobotSKI: fixtures_test.RobotHashedCert,
		},
		Token: &pb.TokenConfig{
			Name:     "FIAT",
			Decimals: uint32(0),
			Issuer:   &pb.Wallet{Address: owner.Address()},
		},
	}

	cfgBytes, _ := protojson.Marshal(cfg)

	init := ledgerMock.NewCC("fiat", NewFiatToken(token.BaseToken{}), string(cfgBytes))
	require.Empty(t, init)

	user := ledgerMock.NewWallet()

	owner.Invoke("acl", "addUser", base58.Encode(owner.PubKey()), "123", "testuser", "true")
	owner.Invoke("acl", "addUser", base58.Encode(user.PubKey()), "123", "testuser", "true")

	owner.SignedInvoke("fiat", "emit", user.Address(), "1000")
}

func TestMultisigEmitTransfer(t *testing.T) {
	ledgerMock := mock.NewLedger(t)
	aclCC := mstub.NewMockStub("acl", New())
	ledgerMock.SetACL(aclCC)
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	aclCC.SetCreator(creator)
	aclCC.MockInit("0", testInitArgs)

	owner := ledgerMock.NewMultisigWallet(3)

	pubKeysEncodedString := make([]string, 0, len(owner.PubKeys()))
	// pubKeysEncodedBytes := make([][]byte, 0, len(owner.PubKeys()))
	for _, memberPk := range owner.PubKeys() {
		owner.Invoke("acl", fnAddUser, base58.Encode(memberPk), "kychash", "testUserID", "true")
		// pubKeysEncodedBytes = append(pubKeysEncodedBytes, []byte(base58.Encode(memberPk)))
		pubKeysEncodedString = append(pubKeysEncodedString, base58.Encode(memberPk))
	}

	nanoNonce := strconv.Itoa(int(time.Now().UnixNano()))
	sourceMsg := append([]string{fnAddMultisig, "3", nanoNonce}, pubKeysEncodedString...)
	message := sha3.Sum256([]byte(strings.Join(sourceMsg, "")))

	// signatures := make([][]byte, 0, len(owner.SecretKeys()))
	signaturesString := make([]string, 0, len(owner.SecretKeys()))
	for _, privkey := range owner.SecretKeys() {
		// signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(privkey, message[:]))))
		signaturesString = append(signaturesString, hex.EncodeToString(ed25519.Sign(privkey, message[:])))
	}

	owner.Invoke("acl", fnAddMultisig, append(sourceMsg[1:], signaturesString...)...)

	cfg := &pb.Config{
		Contract: &pb.ContractConfig{
			Symbol:   "FAIT",
			RobotSKI: fixtures_test.RobotHashedCert,
		},
		Token: &pb.TokenConfig{
			Name:     "FIAT",
			Decimals: uint32(0),
			Issuer:   &pb.Wallet{Address: owner.Address()},
		},
	}
	cfgBytes, _ := protojson.Marshal(cfg)

	init := ledgerMock.NewCC("fiat", NewFiatToken(token.BaseToken{}), string(cfgBytes))
	require.Empty(t, init)

	err = ledgerMock.GetStub("fiat").SetCreatorCert(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)

	user1 := ledgerMock.NewWallet()
	owner.Invoke("acl", fnAddUser, base58.Encode(user1.PubKey()), "kychash", "testUserID", "true")

	_, res, _ := owner.RawSignedInvoke(3, "fiat", "emit", user1.Address(), "1000")
	assert.Equal(t, "", res.Error)
	user1.BalanceShouldBe("fiat", 1000)
}

func TestChangePubkeyMultisigAndEmitTransfer(t *testing.T) {
	ledgerMock := mock.NewLedger(t)
	aclCC := mstub.NewMockStub("acl", New())
	cert, err := getCert(adminCertPath)
	assert.NoError(t, err)
	creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)
	aclCC.SetCreator(creator)
	aclCC.MockInit(
		"0",
		[][]byte{
			[]byte("dc752d6afb51c33327b7873fdb08adb91de15ee7c88f4f9949445aeeb8ea4e99"),
			[]byte("3"),
			[]byte("A4JdE9iZRzU9NEiVDNxYKKWymHeBxHR7mA8AetFrg8m4"),
			[]byte("5Tevazf8xxwyyKGku4VCCSVMDN56mU3mm2WsnENk1zv5"),
			[]byte("6qFz88dv2R8sXmyzWPjvzN6jafv7t1kNUHztYKjH1Rd4"),
		},
	)
	ledgerMock.SetACL(aclCC)

	owner := ledgerMock.NewMultisigWallet(3)

	pubKeysEncodedString := make([]string, 0, len(owner.PubKeys()))
	// pubKeysEncodedBytes := make([][]byte, 0, len(owner.PubKeys()))
	for _, memberPk := range owner.PubKeys() {
		owner.Invoke("acl", fnAddUser, base58.Encode(memberPk), "kychash", "testUserID", "true")
		// pubKeysEncodedBytes = append(pubKeysEncodedBytes, []byte(base58.Encode(memberPk)))
		pubKeysEncodedString = append(pubKeysEncodedString, base58.Encode(memberPk))
	}

	// add multisig
	nanoNonce := strconv.Itoa(int(time.Now().UnixNano()))
	sourceMsg := append([]string{"addMultisig", "3", nanoNonce}, pubKeysEncodedString...)
	message := sha3.Sum256([]byte(strings.Join(sourceMsg, "")))

	// var signatures [][]byte
	signaturesString := make([]string, 0, len(owner.SecretKeys()))
	for _, privkey := range owner.SecretKeys() {
		// signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(privkey, message[:]))))
		signaturesString = append(signaturesString, hex.EncodeToString(ed25519.Sign(privkey, message[:])))
	}

	owner.Invoke("acl", "addMultisig", append(sourceMsg[1:], signaturesString...)...)

	cfg := &pb.Config{
		Contract: &pb.ContractConfig{
			Symbol:   "FIAT",
			RobotSKI: fixtures_test.RobotHashedCert,
		},
		Token: &pb.TokenConfig{
			Name:     "FIAT",
			Decimals: uint32(0),
			Issuer:   &pb.Wallet{Address: owner.Address()},
		},
	}
	cfgBytes, _ := protojson.Marshal(cfg)

	init := ledgerMock.NewCC("fiat", NewFiatToken(token.BaseToken{}), string(cfgBytes))
	require.Empty(t, init)

	err = ledgerMock.GetStub("fiat").SetCreatorCert(testCreatorMSP, cert.Raw)
	assert.NoError(t, err)

	// replace one user's keys
	newPubKey, newSecretKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	oldPubKey := base58.Encode(owner.PubKeys()[0])
	err = owner.ChangeKeysFor(0, newSecretKey)
	assert.NoError(t, err)

	// now owner.PubKeys()[0] is another key (after owner.ChangeKeysFor() invoke)
	owner.Invoke("acl", "addUser", base58.Encode(owner.PubKeys()[0]), "kychash", "testUserID", "true")
	// get new public keys
	validatorsPubKeys := make([]string, 0, len(MockValidatorKeys))
	validatorsSecretKeys := make([]string, 0, len(MockValidatorKeys))
	for pubkey, privkey := range MockValidatorKeys {
		validatorsPubKeys = append(validatorsPubKeys, pubkey)
		validatorsSecretKeys = append(validatorsSecretKeys, privkey)
	}

	newKeys := make([]string, 0, len(owner.PubKeys()))
	for _, newpk := range owner.PubKeys() {
		newKeys = append(newKeys, base58.Encode(newpk))
	}

	// change pubkey in multisig
	newKeysString := strings.Join(newKeys, "/")
	newNanoNonce := strconv.Itoa(int(time.Now().UnixNano()))
	changeMsg := sha3.Sum256([]byte(strings.Join(
		append(
			[]string{"changeMultisigPublicKey", owner.Address(), oldPubKey, newKeysString, "reason", "1", newNanoNonce},
			validatorsPubKeys...,
		),
		"",
	)))

	validatorsSignaturesString := make([]string, 0, len(validatorsSecretKeys))
	for _, privkey := range validatorsSecretKeys {
		validatorsSignaturesString = append(
			validatorsSignaturesString,
			hex.EncodeToString(ed25519.Sign(base58.Decode(privkey), changeMsg[:])),
		)
	}

	// change key
	owner.Invoke("acl", "changeMultisigPublicKey", append(
		append(
			[]string{owner.Address(), oldPubKey, base58.Encode(newPubKey), "reason", "1", newNanoNonce},
			validatorsPubKeys...,
		),
		validatorsSignaturesString...,
	)...)

	user1 := ledgerMock.NewWallet()
	owner.Invoke("acl", "addUser", base58.Encode(user1.PubKey()), "kychash", "testUserID", "true")

	_, res, _ := owner.RawSignedInvoke(3, "fiat", "emit", user1.Address(), "1000")
	assert.Equal(t, "", res.Error)
	user1.BalanceShouldBe("fiat", 1000)

	// check that ReplaceKeysSignedTx committed to token channel too
	compkey, err := shim.CreateCompositeKey(replaceTxChangePrefix, []string{owner.Address()})
	assert.NoError(t, err)
	resp, err := ledgerMock.GetStub("fiat").GetState(compkey)
	assert.NoError(t, err)
	var msg []string
	assert.NoError(t, json.Unmarshal(resp, &msg))
	assert.NotNil(t, msg)
	signedMsgFromACL := append(
		append(
			[]string{"changeMultisigPublicKey", owner.Address(), oldPubKey, newKeysString, "reason", "1", newNanoNonce},
			validatorsPubKeys...,
		),
		validatorsSignaturesString...,
	)
	for index, stx := range signedMsgFromACL {
		assert.Equal(t, stx, msg[index])
	}

	// check that SignedTx committed to token channel too
	compkeySignedTx, err := shim.CreateCompositeKey(signedTxChangePrefix, []string{owner.Address()})
	assert.NoError(t, err)
	respSignedTx, err := ledgerMock.GetStub("fiat").GetState(compkeySignedTx)
	assert.NoError(t, err)
	var msgSignedTx []string
	assert.NoError(t, json.Unmarshal(respSignedTx, &msgSignedTx))
	assert.NotNil(t, msgSignedTx)
	signedTxMsgFromACL := append(
		append(
			[]string{"changeMultisigPublicKey", owner.Address(), oldPubKey, newKeysString, "reason", "1", newNanoNonce},
			validatorsPubKeys...,
		),
		validatorsSignaturesString...,
	)
	for index, stx := range signedTxMsgFromACL {
		assert.Equal(t, stx, msg[index])
	}
}
