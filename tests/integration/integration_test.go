package integration

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/internal/config"
	"github.com/anoideaopen/acl/tests/common"
	"github.com/anoideaopen/foundation/mock"
	mstub "github.com/anoideaopen/foundation/mock/stub"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/unit/fixtures_test"
	"github.com/anoideaopen/foundation/token"
	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	replaceTxChangePrefix = "replacetx"
	signedTxChangePrefix  = "signedtx"
)

func TestAclInitWrongAdminSkiFormat(t *testing.T) {
	aclCC := common.StubCreate(t)

	response := aclCC.MockInit("0", [][]byte{[]byte("a"), []byte("0")})
	require.NotNil(t, response)
	require.Equal(t, int32(500), response.Status)
	require.Equal(t, fmt.Sprintf(config.ErrParsingArgsOld, fmt.Sprintf(config.ErrInvalidAdminSKI, "a")), response.Message)
}

func TestAclInitWrongValidatorCountFormat(t *testing.T) {
	aclCC := common.StubCreate(t)

	response := aclCC.MockInit("0", [][]byte{common.TestAdminSKI, []byte("a")})
	require.NotNil(t, response)
	require.Equal(t, int32(500), response.Status)
	require.Equal(t, fmt.Sprintf(config.ErrParsingArgsOld, fmt.Sprintf(config.ErrInvalidValidatorsCount, "a")), response.Message)
}

func TestAclInitZeroArgs(t *testing.T) {
	aclCC := common.StubCreate(t)

	response := aclCC.MockInit("0", [][]byte{})
	require.NotNil(t, response)
	require.Equal(t, int32(500), response.Status)
	require.Equal(t, fmt.Sprintf(config.ErrParsingArgsOld, fmt.Sprintf(config.ErrArgsLessThanMin, 0, 2)), response.Message)
}

func TestAclInitTwoArgs(t *testing.T) {
	aclCC := common.StubCreate(t)

	testValidatorCount := "0"
	response := aclCC.MockInit("0", [][]byte{common.TestAdminSKI, []byte(testValidatorCount)})
	require.NotNil(t, response)
	require.Equal(t, int32(200), response.Status)
	require.Empty(t, response.Message)

	cfg, err := config.GetConfig(aclCC)
	require.NoError(t, err)
	require.Equal(t, 0, len(cfg.Validators))
	require.Equal(t, string(common.TestAdminSKI), cfg.AdminSKIEncoded)
	require.Equal(t, int64(0), int64(len(cfg.Validators)))
}

func TestAclInitArgs(t *testing.T) {
	aclCC := common.StubCreate(t)

	response := aclCC.MockInit("0", common.TestInitArgs)
	require.NotNil(t, response)
	require.Equal(t, int32(200), response.Status)
	require.Empty(t, response.Message)

	cfg, err := config.GetConfig(aclCC)
	require.NoError(t, err)
	require.Equal(t, len(common.TestValidators), len(cfg.Validators))
}

func TestAclInitConfig(t *testing.T) {
	aclCC := common.StubCreate(t)

	cfgInitBytes, err := protojson.Marshal(common.TestInitConfig)
	require.NoError(t, err)

	var args [][]byte
	args = append(args, cfgInitBytes)

	response := aclCC.MockInit("0", args)
	require.NotNil(t, response)
	require.Equal(t, int32(200), response.Status)
	require.Empty(t, response.Message)

	cfg, err := config.GetConfig(aclCC)
	require.NoError(t, err)
	require.Equal(t, len(common.TestValidators), len(cfg.Validators))
}

func TestEmitTransfer(t *testing.T) {
	ledgerMock := mock.NewLedger(t)
	owner := ledgerMock.NewWallet()

	aclCC := mstub.NewMockStub("acl", cc.New())
	cert, err := common.GetCert(common.AdminCertPath)
	require.NoError(t, err)
	creator, err := common.MarshalIdentity(common.TestCreatorMSP, cert.Raw)
	require.NoError(t, err)
	aclCC.SetCreator(creator)
	aclCC.MockInit("0", common.TestInitArgs)
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

	init := ledgerMock.NewCC("fiat", common.NewFiatToken(token.BaseToken{}), string(cfgBytes))
	require.Empty(t, init)

	user := ledgerMock.NewWallet()

	owner.Invoke("acl", "addUser", base58.Encode(owner.PubKey()), "123", "testuser", "true")
	owner.Invoke("acl", "addUser", base58.Encode(user.PubKey()), "123", "testuser", "true")

	owner.SignedInvoke("fiat", "emit", user.Address(), "1000")
}

func TestMultisigEmitTransfer(t *testing.T) {
	ledgerMock := mock.NewLedger(t)
	aclCC := mstub.NewMockStub("acl", cc.New())
	ledgerMock.SetACL(aclCC)
	cert, err := common.GetCert(common.AdminCertPath)
	require.NoError(t, err)
	creator, err := common.MarshalIdentity(common.TestCreatorMSP, cert.Raw)
	require.NoError(t, err)
	aclCC.SetCreator(creator)
	aclCC.MockInit("0", common.TestInitArgs)

	owner := ledgerMock.NewMultisigWallet(3)

	pubKeysEncodedString := make([]string, 0, len(owner.PubKeys()))
	// pubKeysEncodedBytes := make([][]byte, 0, len(owner.PubKeys()))
	for _, memberPk := range owner.PubKeys() {
		owner.Invoke("acl", common.FnAddUser, base58.Encode(memberPk), "kychash", "testUserID", "true")
		// pubKeysEncodedBytes = append(pubKeysEncodedBytes, []byte(base58.Encode(memberPk)))
		pubKeysEncodedString = append(pubKeysEncodedString, base58.Encode(memberPk))
	}

	nanoNonce := strconv.Itoa(int(time.Now().UnixNano()))
	sourceMsg := append([]string{common.FnAddMultisig, "3", nanoNonce}, pubKeysEncodedString...)
	message := sha3.Sum256([]byte(strings.Join(sourceMsg, "")))

	// signatures := make([][]byte, 0, len(owner.SecretKeys()))
	signaturesString := make([]string, 0, len(owner.SecretKeys()))
	for _, privateKey := range owner.SecretKeys() {
		// signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(privateKey, message[:]))))
		signaturesString = append(signaturesString, hex.EncodeToString(ed25519.Sign(privateKey, message[:])))
	}

	owner.Invoke("acl", common.FnAddMultisig, append(sourceMsg[1:], signaturesString...)...)

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

	init := ledgerMock.NewCC("fiat", common.NewFiatToken(token.BaseToken{}), string(cfgBytes))
	require.Empty(t, init)

	err = ledgerMock.GetStub("fiat").SetCreatorCert(common.TestCreatorMSP, cert.Raw)
	require.NoError(t, err)

	user1 := ledgerMock.NewWallet()
	owner.Invoke("acl", common.FnAddUser, base58.Encode(user1.PubKey()), "kychash", "testUserID", "true")

	_, res, _ := owner.RawSignedInvoke(3, "fiat", "emit", user1.Address(), "1000")
	require.Equal(t, "", res.Error)
	user1.BalanceShouldBe("fiat", 1000)
}

func TestChangePubKeyMultisigAndEmitTransfer(t *testing.T) {
	ledgerMock := mock.NewLedger(t)
	aclCC := mstub.NewMockStub("acl", cc.New())
	cert, err := common.GetCert(common.AdminCertPath)
	require.NoError(t, err)
	creator, err := common.MarshalIdentity(common.TestCreatorMSP, cert.Raw)
	require.NoError(t, err)
	aclCC.SetCreator(creator)
	aclCC.MockInit(
		"0",
		[][]byte{
			common.TestAdminSKI,
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
		owner.Invoke("acl", common.FnAddUser, base58.Encode(memberPk), "kychash", "testUserID", "true")
		// pubKeysEncodedBytes = append(pubKeysEncodedBytes, []byte(base58.Encode(memberPk)))
		pubKeysEncodedString = append(pubKeysEncodedString, base58.Encode(memberPk))
	}

	// add multisig
	nanoNonce := strconv.Itoa(int(time.Now().UnixNano()))
	sourceMsg := append([]string{"addMultisig", "3", nanoNonce}, pubKeysEncodedString...)
	message := sha3.Sum256([]byte(strings.Join(sourceMsg, "")))

	// var signatures [][]byte
	signaturesString := make([]string, 0, len(owner.SecretKeys()))
	for _, privateKey := range owner.SecretKeys() {
		// signatures = append(signatures, []byte(hex.EncodeToString(ed25519.Sign(privateKey, message[:]))))
		signaturesString = append(signaturesString, hex.EncodeToString(ed25519.Sign(privateKey, message[:])))
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

	init := ledgerMock.NewCC("fiat", common.NewFiatToken(token.BaseToken{}), string(cfgBytes))
	require.Empty(t, init)

	err = ledgerMock.GetStub("fiat").SetCreatorCert(common.TestCreatorMSP, cert.Raw)
	require.NoError(t, err)

	// replace one user's keys
	newPubKey, newSecretKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	oldPubKey := base58.Encode(owner.PubKeys()[0])
	err = owner.ChangeKeysFor(0, newSecretKey)
	require.NoError(t, err)

	// now owner.PubKeys()[0] is another key (after owner.ChangeKeysFor() invoke)
	owner.Invoke("acl", "addUser", base58.Encode(owner.PubKeys()[0]), "kychash", "testUserID", "true")
	// get new public keys
	validatorsPubKeys := make([]string, 0, len(common.MockValidatorKeys))
	validatorsSecretKeys := make([]string, 0, len(common.MockValidatorKeys))
	for pubKey, privateKey := range common.MockValidatorKeys {
		validatorsPubKeys = append(validatorsPubKeys, pubKey)
		validatorsSecretKeys = append(validatorsSecretKeys, privateKey)
	}

	newKeys := make([]string, 0, len(owner.PubKeys()))
	for _, newPk := range owner.PubKeys() {
		newKeys = append(newKeys, base58.Encode(newPk))
	}

	// change pubKey in multisig
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
	for _, privateKey := range validatorsSecretKeys {
		validatorsSignaturesString = append(
			validatorsSignaturesString,
			hex.EncodeToString(ed25519.Sign(base58.Decode(privateKey), changeMsg[:])),
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
	require.Equal(t, "", res.Error)
	user1.BalanceShouldBe("fiat", 1000)

	// check that ReplaceKeysSignedTx committed to token channel too
	compKey, err := shim.CreateCompositeKey(replaceTxChangePrefix, []string{owner.Address()})
	require.NoError(t, err)
	resp, err := ledgerMock.GetStub("fiat").GetState(compKey)
	require.NoError(t, err)
	var msg []string
	require.NoError(t, json.Unmarshal(resp, &msg))
	require.NotNil(t, msg)
	signedMsgFromACL := append(
		append(
			[]string{"changeMultisigPublicKey", owner.Address(), oldPubKey, newKeysString, "reason", "1", newNanoNonce},
			validatorsPubKeys...,
		),
		validatorsSignaturesString...,
	)
	for index, stx := range signedMsgFromACL {
		require.Equal(t, stx, msg[index])
	}

	// check that SignedTx committed to token channel too
	compKeySignedTx, err := shim.CreateCompositeKey(signedTxChangePrefix, []string{owner.Address()})
	require.NoError(t, err)
	respSignedTx, err := ledgerMock.GetStub("fiat").GetState(compKeySignedTx)
	require.NoError(t, err)
	var msgSignedTx []string
	require.NoError(t, json.Unmarshal(respSignedTx, &msgSignedTx))
	require.NotNil(t, msgSignedTx)
	signedTxMsgFromACL := append(
		append(
			[]string{"changeMultisigPublicKey", owner.Address(), oldPubKey, newKeysString, "reason", "1", newNanoNonce},
			validatorsPubKeys...,
		),
		validatorsSignaturesString...,
	)
	for index, stx := range signedTxMsgFromACL {
		require.Equal(t, stx, msg[index])
	}
}
