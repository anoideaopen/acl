package cc

import (
	"testing"

	"github.com/anoideaopen/foundation/mock"
	mstub "github.com/anoideaopen/foundation/mock/stub"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/unit/fixtures_test"
	"github.com/anoideaopen/foundation/token"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	channelName   = "BA"
	chaincodeName = "IVT.BAR"
	roleName      = "issuer"
	operationName = ""
)

func TestAclAccessMatrix(t *testing.T) {
	var mockStub *shimtest.MockStub
	t.Run("Initializing acl stub", func(t *testing.T) {
		mockStub = shimtest.NewMockStub("mockStub", New())
		assert.NotNil(t, mockStub, "MockStub creation failed")

		cert, err := getCert(adminCertPath)
		assert.NoError(t, err)
		err = SetCreator(mockStub, testCreatorMSP, cert.Raw)
		assert.NoError(t, err)
		resp := mockStub.MockInit("0", testInitArgs)
		assert.Equal(t, int32(shim.OK), resp.Status)
	})

	// check address
	hashed := sha3.Sum256(base58.Decode(pubkey))
	addr := base58.CheckEncode(hashed[1:], hashed[0])

	t.Run("Adding user", func(t *testing.T) {
		resp := mockStub.MockInvoke("0", [][]byte{
			[]byte(fnAddUser),
			[]byte(pubkey),
			[]byte("kychash"),
			[]byte("testUserID"),
			[]byte("true"),
		})
		assert.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Adding new user right", func(t *testing.T) {
		resp := mockStub.MockInvoke("0", [][]byte{
			[]byte(fnAddRights),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		assert.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Checking if right was added", func(t *testing.T) {
		result := mockStub.MockInvoke("0", [][]byte{
			[]byte(fnGetAccOpRight),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.HaveRight{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.HaveRight)
		assert.Equal(t, true, response.HaveRight, "right was not added")
	})

	t.Run("Checking user rights", func(t *testing.T) {
		result := mockStub.MockInvoke("0", [][]byte{
			[]byte(fnGetAccAllRights),
			[]byte(addr),
		})
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AccountRights{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.Address)
		assert.NotNil(t, response.Rights)
		assert.Equal(t, addr, response.Address.AddrString(), "wrong address")
		assert.Len(t, response.Rights, 1)
		assert.Equal(t, channelName, response.Rights[0].ChannelName)
		assert.Equal(t, chaincodeName, response.Rights[0].ChaincodeName)
		assert.Equal(t, roleName, response.Rights[0].RoleName)
		assert.Equal(t, operationName, response.Rights[0].OperationName)
		assert.Equal(t, addr, response.Rights[0].Address.AddrString())
		assert.NotNil(t, response.Rights[0].HaveRight)
		assert.Equal(t, true, response.Rights[0].HaveRight.HaveRight)
	})

	t.Run("[negative] Check operation rights by user", func(t *testing.T) {
		ucert, err := getCert(userCertPath)
		assert.NoError(t, err)
		assert.NotNil(t, ucert)
		err = SetCreator(mockStub, testCreatorMSP, ucert.Raw)
		assert.NoError(t, err)

		result := mockStub.MockInvoke("1", [][]byte{
			[]byte(fnGetAccOpRight),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		assert.Equal(t, int32(shim.ERROR), result.Status)
		assert.Equal(t, ErrCalledNotCCOrAdmin, result.Message)
	})

	t.Run("Checking operation rights", func(t *testing.T) {
		cert, err := getCert(adminCertPath)
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		err = SetCreator(mockStub, testCreatorMSP, cert.Raw)
		assert.NoError(t, err)

		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(fnGetOpAllRights),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(roleName),
				[]byte(operationName),
			},
		)
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.OperationRights{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.OperationName)
		assert.NotNil(t, response.Rights)
		assert.Equal(t, operationName, response.OperationName, "wrong address")
		assert.Len(t, response.Rights, 1)
		assert.Equal(t, channelName, response.Rights[0].ChannelName)
		assert.Equal(t, chaincodeName, response.Rights[0].ChaincodeName)
		assert.Equal(t, roleName, response.Rights[0].RoleName)
		assert.Equal(t, operationName, response.Rights[0].OperationName)
		assert.Equal(t, addr, response.Rights[0].Address.AddrString())
		assert.NotNil(t, response.Rights[0].HaveRight)
		assert.Equal(t, true, response.Rights[0].HaveRight.HaveRight)
	})

	t.Run("Adding new user right", func(t *testing.T) {
		resp := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(fnAddRights),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(roleName),
				[]byte(operationName),
				[]byte(addr),
			},
		)
		assert.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Adding same user right again", func(t *testing.T) {
		resp := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(fnAddRights),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(roleName),
				[]byte(operationName),
				[]byte(addr),
			},
		)
		assert.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Removing right", func(t *testing.T) {
		resp := mockStub.MockInvoke("0", [][]byte{
			[]byte(fnRemoveRights),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		assert.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Checking if right was removed", func(t *testing.T) {
		result := mockStub.MockInvoke("0", [][]byte{
			[]byte(fnGetAccOpRight),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.HaveRight{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.HaveRight)
		assert.Equal(t, false, response.HaveRight, "right was not added")
	})

	t.Run("Checking user rights", func(t *testing.T) {
		result := mockStub.MockInvoke("0", [][]byte{[]byte(fnGetAccAllRights), []byte(addr)})
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AccountRights{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.Address)
		assert.Nil(t, response.Rights)
		assert.Equal(t, addr, response.Address.AddrString(), "wrong address")
		assert.Len(t, response.Rights, 0)
	})

	t.Run("Checking operation rights", func(t *testing.T) {
		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(fnGetOpAllRights),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(roleName),
				[]byte(operationName),
			},
		)
		assert.Equal(t, int32(shim.OK), result.Status)

		response := &pb.OperationRights{}
		assert.NoError(t, proto.Unmarshal(result.Payload, response))
		assert.NotNil(t, response.OperationName)
		assert.Nil(t, response.Rights)
		assert.Equal(t, operationName, response.OperationName, "wrong address")
		assert.Len(t, response.Rights, 0)
	})
}

func TestAclCalledFromChaincode(t *testing.T) {
	ledgerMock := mock.NewLedger(t)
	owner := ledgerMock.NewWallet()

	t.Run("Initializing acl chaincode", func(t *testing.T) {
		aclCC := mstub.NewMockStub("acl", New())
		cert, err := getCert(adminCertPath)
		assert.NoError(t, err)
		creator, err := marshalIdentity(testCreatorMSP, cert.Raw)
		assert.NoError(t, err)
		aclCC.SetCreator(creator)
		aclCC.MockInit("0", testInitArgs)
		ledgerMock.SetACL(aclCC)
	})

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

	owner.Invoke("acl", "addUser", base58.Encode(owner.PubKey()), "123", "testuser", "true")
	user := ledgerMock.NewWallet()
	owner.Invoke("acl", "addUser", base58.Encode(user.PubKey()), "234", "testuser2", "true")
	owner.Invoke("acl", "addRights", "fiat", "fiat", "issuer", "someMethod", user.Address())

	result := owner.Invoke("fiat", "getRight", "fiat", "fiat", "issuer", "someMethod", user.Address())
	assert.Equal(t, "true", result)
}
