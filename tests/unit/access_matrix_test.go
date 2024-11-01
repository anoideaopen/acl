package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/anoideaopen/foundation/mock"
	mstub "github.com/anoideaopen/foundation/mock/stub"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/unit/fixtures_test"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest" //nolint:staticcheck
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
		mockStub = common.StubCreateAndInit(t)
	})

	// check address
	hashed := sha3.Sum256(base58.Decode(common.PubKey))
	addr := base58.CheckEncode(hashed[1:], hashed[0])

	t.Run("Adding user", func(t *testing.T) {
		resp := mockStub.MockInvoke("0", [][]byte{
			[]byte(common.FnAddUser),
			[]byte(common.PubKey),
			[]byte("kychash"),
			[]byte("testUserID"),
			[]byte("true"),
		})
		require.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Adding new user right", func(t *testing.T) {
		resp := mockStub.MockInvoke("0", [][]byte{
			[]byte(common.FnAddRights),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		require.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Checking if right was added", func(t *testing.T) {
		result := mockStub.MockInvoke("0", [][]byte{
			[]byte(common.FnGetAccOpRight),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.HaveRight{}
		require.NoError(t, proto.Unmarshal(result.Payload, response))
		require.NotNil(t, response.HaveRight)
		require.Equal(t, true, response.HaveRight, "right was not added")
	})

	t.Run("Checking user rights", func(t *testing.T) {
		result := mockStub.MockInvoke("0", [][]byte{
			[]byte(common.FnGetAccAllRights),
			[]byte(addr),
		})
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AccountRights{}
		require.NoError(t, protojson.Unmarshal(result.Payload, response))
		require.NotNil(t, response.Address)
		require.NotNil(t, response.Rights)
		require.Equal(t, addr, response.Address.AddrString(), "wrong address")
		require.Len(t, response.Rights, 1)
		require.Equal(t, channelName, response.Rights[0].ChannelName)
		require.Equal(t, chaincodeName, response.Rights[0].ChaincodeName)
		require.Equal(t, roleName, response.Rights[0].RoleName)
		require.Equal(t, operationName, response.Rights[0].OperationName)
		require.Equal(t, addr, response.Rights[0].Address.AddrString())
		require.NotNil(t, response.Rights[0].HaveRight)
		require.Equal(t, true, response.Rights[0].HaveRight.HaveRight)
	})

	t.Run("[negative] Check operation rights by user", func(t *testing.T) {
		uCert, err := common.GetCert(common.UserCertPath)
		require.NoError(t, err)
		require.NotNil(t, uCert)
		err = common.SetCreator(mockStub, common.TestCreatorMSP, uCert.Raw)
		require.NoError(t, err)

		result := mockStub.MockInvoke("1", [][]byte{
			[]byte(common.FnGetAccOpRight),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		require.Equal(t, int32(shim.ERROR), result.Status)
		require.Contains(t, result.Message, errs.ErrCalledNotCCOrAdmin)
	})

	t.Run("Checking operation rights", func(t *testing.T) {
		cert, err := common.GetCert(common.AdminCertPath)
		require.NoError(t, err)
		require.NotNil(t, cert)
		err = common.SetCreator(mockStub, common.TestCreatorMSP, cert.Raw)
		require.NoError(t, err)

		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnGetOpAllRights),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(roleName),
				[]byte(operationName),
			},
		)
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.OperationRights{}
		require.NoError(t, protojson.Unmarshal(result.Payload, response))
		require.NotNil(t, response.OperationName)
		require.NotNil(t, response.Rights)
		require.Equal(t, operationName, response.OperationName, "wrong address")
		require.Len(t, response.Rights, 1)
		require.Equal(t, channelName, response.Rights[0].ChannelName)
		require.Equal(t, chaincodeName, response.Rights[0].ChaincodeName)
		require.Equal(t, roleName, response.Rights[0].RoleName)
		require.Equal(t, operationName, response.Rights[0].OperationName)
		require.Equal(t, addr, response.Rights[0].Address.AddrString())
		require.NotNil(t, response.Rights[0].HaveRight)
		require.Equal(t, true, response.Rights[0].HaveRight.HaveRight)
	})

	t.Run("Adding new user right", func(t *testing.T) {
		resp := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnAddRights),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(roleName),
				[]byte(operationName),
				[]byte(addr),
			},
		)
		require.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Adding same user right again", func(t *testing.T) {
		resp := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnAddRights),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(roleName),
				[]byte(operationName),
				[]byte(addr),
			},
		)
		require.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Removing right", func(t *testing.T) {
		resp := mockStub.MockInvoke("0", [][]byte{
			[]byte(common.FnRemoveRights),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		require.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("Checking if right was removed", func(t *testing.T) {
		result := mockStub.MockInvoke("0", [][]byte{
			[]byte(common.FnGetAccOpRight),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(roleName),
			[]byte(operationName),
			[]byte(addr),
		})
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.HaveRight{}
		require.NoError(t, proto.Unmarshal(result.Payload, response))
		require.NotNil(t, response.HaveRight)
		require.Equal(t, false, response.HaveRight, "right was not added")
	})

	t.Run("Checking user rights", func(t *testing.T) {
		result := mockStub.MockInvoke("0", [][]byte{[]byte(common.FnGetAccAllRights), []byte(addr)})
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.AccountRights{}
		require.NoError(t, protojson.Unmarshal(result.Payload, response))
		require.NotNil(t, response.Address)
		require.Nil(t, response.Rights)
		require.Equal(t, addr, response.Address.AddrString(), "wrong address")
		require.Len(t, response.Rights, 0)
	})

	t.Run("Checking operation rights", func(t *testing.T) {
		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnGetOpAllRights),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(roleName),
				[]byte(operationName),
			},
		)
		require.Equal(t, int32(shim.OK), result.Status)

		response := &pb.OperationRights{}
		require.NoError(t, protojson.Unmarshal(result.Payload, response))
		require.NotNil(t, response.OperationName)
		require.Nil(t, response.Rights)
		require.Equal(t, operationName, response.OperationName, "wrong address")
		require.Len(t, response.Rights, 0)
	})

	principalUser := common.TestUsers[0]
	principalHashed := sha3.Sum256(base58.Decode(principalUser.PublicKey))
	principalAddress := base58.CheckEncode(principalHashed[1:], principalHashed[0])

	t.Run("Adding user", func(t *testing.T) {
		resp := mockStub.MockInvoke("0", [][]byte{
			[]byte(common.FnAddUser),
			[]byte(principalUser.PublicKey),
			[]byte("kychash"),
			[]byte("testUserID"),
			[]byte("true"),
		})
		require.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("adding principal address for nominee", func(t *testing.T) {
		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnAddAddressForNominee),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(addr),
				[]byte(principalAddress),
			},
		)
		require.Equal(t, int32(shim.OK), result.Status)
	})

	t.Run("checking nominee addresses", func(t *testing.T) {
		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnGetAddressesListForNominee),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(addr),
			},
		)

		addresses := &pb.Accounts{}
		require.NoError(t, protojson.Unmarshal(result.Payload, addresses))
		require.Equal(t, 1, len(addresses.GetAddresses()))
		require.Equal(t, principalAddress, addresses.GetAddresses()[0].AddrString())
	})

	t.Run("[negative] checking nominee right by user", func(t *testing.T) {
		uCert, err := common.GetCert(common.UserCertPath)
		require.NoError(t, err)
		require.NotNil(t, uCert)
		err = common.SetCreator(mockStub, common.TestCreatorMSP, uCert.Raw)
		require.NoError(t, err)

		result := mockStub.MockInvoke("1", [][]byte{
			[]byte(common.FnGetAddressRightForNominee),
			[]byte(channelName),
			[]byte(chaincodeName),
			[]byte(addr),
			[]byte(principalAddress),
		})
		require.Equal(t, int32(shim.ERROR), result.Status)
		require.Contains(t, result.Message, errs.ErrCalledNotCCOrAdmin)
	})

	t.Run("adding address again", func(t *testing.T) {
		cert, err := common.GetCert(common.AdminCertPath)
		require.NoError(t, err)
		require.NotNil(t, cert)
		err = common.SetCreator(mockStub, common.TestCreatorMSP, cert.Raw)
		require.NoError(t, err)

		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnAddAddressForNominee),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(addr),
				[]byte(principalAddress),
			},
		)
		require.Equal(t, int32(shim.OK), result.Status)
	})

	t.Run("checking if address was not added", func(t *testing.T) {
		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnGetAddressesListForNominee),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(addr),
			},
		)

		addresses := &pb.Accounts{}
		require.NoError(t, protojson.Unmarshal(result.Payload, addresses))
		require.Equal(t, 1, len(addresses.GetAddresses()))
		require.Equal(t, principalAddress, addresses.GetAddresses()[0].AddrString())
	})

	t.Run("removing address", func(t *testing.T) {
		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnRemoveAddressFromNominee),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(addr),
				[]byte(principalAddress),
			},
		)
		require.Equal(t, int32(shim.OK), result.Status)
	})

	t.Run("checking if address was removed", func(t *testing.T) {
		result := mockStub.MockInvoke(
			"0",
			[][]byte{
				[]byte(common.FnGetAddressesListForNominee),
				[]byte(channelName),
				[]byte(chaincodeName),
				[]byte(addr),
			},
		)

		addresses := &pb.Accounts{}
		require.NoError(t, protojson.Unmarshal(result.Payload, addresses))
		require.Equal(t, 0, len(addresses.GetAddresses()))
	})
}

func TestAclCalledFromChaincode(t *testing.T) {
	ledgerMock := mock.NewLedger(t)
	owner := ledgerMock.NewWallet()

	t.Run("Initializing acl chaincode", func(t *testing.T) {
		aclCC := mstub.NewMockStub("acl", cc.New())
		cert, err := common.GetCert(common.AdminCertPath)
		require.NoError(t, err)
		creator, err := common.MarshalIdentity(common.TestCreatorMSP, cert.Raw)
		require.NoError(t, err)
		aclCC.SetCreator(creator)
		aclCC.MockInit("0", common.TestInitArgs)
		ledgerMock.SetACL(aclCC)
	})

	t.Run("Initializing fiat chaincode", func(t *testing.T) {
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

		init := ledgerMock.NewCC("fiat", common.NewFiatToken(), string(cfgBytes))
		require.Empty(t, init)
	})

	user := ledgerMock.NewWallet()
	ownerPkB58 := base58.Encode(owner.PubKey())
	userPkB58 := base58.Encode(user.PubKey())

	t.Run("Requesting rights from fiat", func(t *testing.T) {
		owner.Invoke("acl", "addUser", ownerPkB58, "123", "testuser", "true")
		owner.Invoke("acl", "addUser", userPkB58, "234", "testuser2", "true")
		owner.Invoke("acl", "addRights", "fiat", "fiat", "issuer", "someMethod", user.Address())

		result := owner.Invoke("fiat", "getRight", "fiat", "fiat", "issuer", "someMethod", user.Address())
		require.Equal(t, "true", result)
	})

	t.Run("Requesting addresses for nominee from fiat", func(t *testing.T) {
		owner.Invoke("acl", common.FnAddAddressForNominee, "fiat", "fiat", owner.Address(), user.Address())

		result := owner.Invoke("fiat", common.FnGetAddressRightForNominee, "fiat", "fiat", owner.Address(), user.Address())
		require.Equal(t, "true", result)
	})
}
