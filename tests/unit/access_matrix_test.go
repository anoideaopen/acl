package unit

import (
	"encoding/hex"
	"testing"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/cc/compositekey"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/unit/common"
	"github.com/anoideaopen/acl/tests/unit/mock"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	operationKey        = "acl_access_matrix_operation"
	addressKey          = "acl_access_matrix_address"
	nomineeAddressesKey = "acl_access_matrix_principal_addresses"
	channelName         = "BA"
	chaincodeName       = "IVT.BAR"
	roleName            = "issuer"
	operationName       = ""
)

func TestAclAccessMatrix(t *testing.T) {
	t.Parallel()

	hashed := sha3.Sum256(base58.Decode(common.PubKey))
	addr := base58.CheckEncode(hashed[1:], hashed[0])

	principalUser := common.TestUsers[0]
	principalHashed := sha3.Sum256(base58.Decode(principalUser.PublicKey))
	principalAddress := base58.CheckEncode(principalHashed[1:], principalHashed[0])
	principalHashInHex := hex.EncodeToString(principalHashed[:])

	keyPk, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{common.TestAddr})
	require.NoError(t, err)
	keyAccountInfo, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{common.TestAddr})
	require.NoError(t, err)
	keyAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{common.TestAddrHashInHex})
	require.NoError(t, err)
	keyOperationMatrix, err := shim.CreateCompositeKey(operationKey, []string{channelName, chaincodeName, roleName, operationName})
	require.NoError(t, err)
	keyAddresMatrix, err := shim.CreateCompositeKey(addressKey, []string{common.TestAddr})
	require.NoError(t, err)
	keyNomineeAddresses, err := shim.CreateCompositeKey(nomineeAddressesKey, []string{channelName, chaincodeName, addr})
	require.NoError(t, err)

	keyPrincipalPk, err := shim.CreateCompositeKey(compositekey.PublicKeyPrefix, []string{principalAddress})
	require.NoError(t, err)
	keyPrincipalAccountInfo, err := shim.CreateCompositeKey(compositekey.AccountInfoPrefix, []string{principalAddress})
	require.NoError(t, err)
	keyPrincipalAddress, err := shim.CreateCompositeKey(compositekey.SignedAddressPrefix, []string{principalHashInHex})
	require.NoError(t, err)

	signPrincipalAddr := &pb.SignedAddress{
		Address: &pb.Address{
			UserID:       "testUserID",
			Address:      principalHashed[:],
			IsIndustrial: true,
		},
	}

	accountInfo := &pb.AccountInfo{
		KycHash: kycHash,
	}
	signAddr := &pb.SignedAddress{
		Address: &pb.Address{
			UserID:       "testUserID",
			Address:      hashed[:],
			IsIndustrial: true,
		},
	}
	accounts := &pb.Accounts{
		Addresses: []*pb.Address{
			{
				UserID:       "testUserID",
				Address:      hashed[:],
				IsIndustrial: true,
			},
		},
	}
	accountsPrincipal := &pb.Accounts{
		Addresses: []*pb.Address{
			{
				UserID:       "testUserID",
				Address:      principalHashed[:],
				IsIndustrial: true,
			},
		},
	}
	accountRights := &pb.AccountRights{
		Address: &pb.Address{
			UserID:       "testUserID",
			Address:      hashed[:],
			IsIndustrial: true,
		},
		Rights: []*pb.Right{
			{
				ChannelName:   channelName,
				ChaincodeName: chaincodeName,
				RoleName:      roleName,
				OperationName: operationName,
				Address: &pb.Address{
					UserID:       "testUserID",
					Address:      hashed[:],
					IsIndustrial: true,
				},
				HaveRight: &pb.HaveRight{HaveRight: true},
			},
		},
	}

	for _, testCase := range []struct {
		description string
		fn          string
		args        []string
		respStatus  int32
		errorMsg    string
		getFn       func(s string) ([]byte, error)
		checkFn     func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte)
		cert        string
	}{
		{
			description: "add rights",
			fn:          common.FnAddRights,
			args:        []string{channelName, chaincodeName, roleName, operationName, addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				require.Equal(t, 2, mockStub.PutStateCallCount())

				keyState, val := mockStub.PutStateArgsForCall(0)
				require.Equal(t, keyState, keyOperationMatrix)
				accountsState := &pb.Accounts{}
				require.NoError(t, protojson.Unmarshal(val, accountsState))
				require.True(t, proto.Equal(accountsState, accounts))

				keyState, val = mockStub.PutStateArgsForCall(1)
				require.Equal(t, keyState, keyAddresMatrix)
				accountRightsState := &pb.AccountRights{}
				require.NoError(t, protojson.Unmarshal(val, accountRightsState))
				require.True(t, proto.Equal(accountRightsState, accountRights))
			},
		},
		{
			description: "add rights again",
			fn:          common.FnAddRights,
			args:        []string{channelName, chaincodeName, roleName, operationName, addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyOperationMatrix:
					return protojson.Marshal(accounts)
				case keyAddresMatrix:
					return protojson.Marshal(accountRights)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				require.Equal(t, 0, mockStub.PutStateCallCount())
			},
		},
		{
			description: "remove rights",
			fn:          common.FnRemoveRights,
			args:        []string{channelName, chaincodeName, roleName, operationName, addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyOperationMatrix:
					return protojson.Marshal(accounts)
				case keyAddresMatrix:
					return protojson.Marshal(accountRights)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				require.Equal(t, 2, mockStub.PutStateCallCount())

				keyState, val := mockStub.PutStateArgsForCall(0)
				require.Equal(t, keyState, keyOperationMatrix)
				accountsState := &pb.Accounts{}
				require.NoError(t, protojson.Unmarshal(val, accountsState))
				require.True(t, proto.Equal(accountsState, &pb.Accounts{
					Addresses: []*pb.Address{},
				}))

				keyState, val = mockStub.PutStateArgsForCall(1)
				require.Equal(t, keyState, keyAddresMatrix)
				accountRightsState := &pb.AccountRights{}
				require.NoError(t, protojson.Unmarshal(val, accountRightsState))
				require.True(t, proto.Equal(accountRightsState, &pb.AccountRights{
					Address: signAddr.Address,
					Rights:  []*pb.Right{},
				}))
			},
		},
		{
			description: "get account operation right check if added",
			fn:          common.FnGetAccOpRight,
			args:        []string{channelName, chaincodeName, roleName, operationName, addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyOperationMatrix:
					return protojson.Marshal(accounts)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				hr := &pb.HaveRight{}
				require.NoError(t, proto.Unmarshal(payload, hr))
				require.True(t, proto.Equal(hr, &pb.HaveRight{HaveRight: true}))
			},
		},
		{
			description: "get account operation right check if removed",
			fn:          common.FnGetAccOpRight,
			args:        []string{channelName, chaincodeName, roleName, operationName, addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyOperationMatrix:
					return protojson.Marshal(&pb.Accounts{
						Addresses: []*pb.Address{},
					})
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				hr := &pb.HaveRight{}
				require.NoError(t, proto.Unmarshal(payload, hr))
				require.True(t, proto.Equal(hr, &pb.HaveRight{}))
			},
		},
		{
			description: "get account operation right bad certificate",
			fn:          common.FnGetAccOpRight,
			args:        []string{channelName, chaincodeName, roleName, operationName, addr},
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrCalledNotCCOrAdmin,
			cert:        common.UserCert,
		},
		{
			description: "get account all rights check if added",
			fn:          common.FnGetAccAllRights,
			args:        []string{addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyAddresMatrix:
					return protojson.Marshal(accountRights)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				ar := &pb.AccountRights{}
				require.NoError(t, protojson.Unmarshal(payload, ar))
				require.True(t, proto.Equal(ar, accountRights))
			},
		},
		{
			description: "get account all rights check if removed",
			fn:          common.FnGetAccAllRights,
			args:        []string{addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyAddresMatrix:
					return protojson.Marshal(&pb.AccountRights{
						Address: signAddr.Address,
						Rights:  []*pb.Right{},
					})
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				ar := &pb.AccountRights{}
				require.NoError(t, protojson.Unmarshal(payload, ar))
				require.True(t, proto.Equal(ar, &pb.AccountRights{
					Address: signAddr.Address,
					Rights:  []*pb.Right{},
				}))
			},
		},
		{
			description: "get operation all rights check if added",
			fn:          common.FnGetOpAllRights,
			args:        []string{channelName, chaincodeName, roleName, operationName},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyOperationMatrix:
					return protojson.Marshal(accounts)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				or := &pb.OperationRights{}
				require.NoError(t, protojson.Unmarshal(payload, or))
				require.True(t, proto.Equal(or, &pb.OperationRights{
					OperationName: operationName,
					Rights:        accountRights.Rights,
				}))
			},
		},
		{
			description: "get operation all rights check if removed",
			fn:          common.FnGetOpAllRights,
			args:        []string{channelName, chaincodeName, roleName, operationName},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyOperationMatrix:
					return protojson.Marshal(&pb.Accounts{
						Addresses: []*pb.Address{},
					})
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				or := &pb.OperationRights{}
				require.NoError(t, protojson.Unmarshal(payload, or))
				require.True(t, proto.Equal(or, &pb.OperationRights{OperationName: operationName}))
			},
		},
		{
			description: "add address for nominee",
			fn:          common.FnAddAddressForNominee,
			args:        []string{channelName, chaincodeName, addr, principalAddress},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyPrincipalPk:
					return []byte(principalHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyPrincipalAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyPrincipalAddress:
					return proto.Marshal(signPrincipalAddr)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				require.Equal(t, 1, mockStub.PutStateCallCount())

				keyState, val := mockStub.PutStateArgsForCall(0)
				require.Equal(t, keyState, keyNomineeAddresses)
				accountsState := &pb.Accounts{}
				require.NoError(t, protojson.Unmarshal(val, accountsState))
				require.True(t, proto.Equal(accountsState, accountsPrincipal))
			},
		},
		{
			description: "add address for nominee again",
			fn:          common.FnAddAddressForNominee,
			args:        []string{channelName, chaincodeName, addr, principalAddress},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyPrincipalPk:
					return []byte(principalHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyPrincipalAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyPrincipalAddress:
					return proto.Marshal(signPrincipalAddr)
				case keyNomineeAddresses:
					return protojson.Marshal(accountsPrincipal)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				require.Equal(t, 0, mockStub.PutStateCallCount())
			},
		},
		{
			description: "remove address from nominee",
			fn:          common.FnRemoveAddressFromNominee,
			args:        []string{channelName, chaincodeName, addr, principalAddress},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyPrincipalPk:
					return []byte(principalHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyPrincipalAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyPrincipalAddress:
					return proto.Marshal(signPrincipalAddr)
				case keyNomineeAddresses:
					return protojson.Marshal(accountsPrincipal)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				require.Equal(t, 1, mockStub.PutStateCallCount())

				keyState, val := mockStub.PutStateArgsForCall(0)
				require.Equal(t, keyState, keyNomineeAddresses)
				accountsState := &pb.Accounts{}
				require.NoError(t, protojson.Unmarshal(val, accountsState))
				require.True(t, proto.Equal(accountsState, &pb.Accounts{Addresses: []*pb.Address{}}))
			},
		},
		{
			description: "checking nominee right by bad certificate",
			fn:          common.FnGetAddressRightForNominee,
			args:        []string{channelName, chaincodeName, addr, principalAddress},
			respStatus:  int32(shim.ERROR),
			errorMsg:    errs.ErrCalledNotCCOrAdmin,
			cert:        common.UserCert,
		},
		{
			description: "checking nominee if addresses added",
			fn:          common.FnGetAddressesListForNominee,
			args:        []string{channelName, chaincodeName, addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyNomineeAddresses:
					return protojson.Marshal(accountsPrincipal)
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				ac := &pb.Accounts{}
				require.NoError(t, protojson.Unmarshal(payload, ac))
				require.True(t, proto.Equal(ac, accountsPrincipal))
			},
		},
		{
			description: "checking nominee if addresses removed",
			fn:          common.FnGetAddressesListForNominee,
			args:        []string{channelName, chaincodeName, addr},
			respStatus:  int32(shim.OK),
			getFn: func(s string) ([]byte, error) {
				switch s {
				case keyPk:
					return []byte(common.TestAddrHashInHex), nil
				case keyAccountInfo:
					return proto.Marshal(accountInfo)
				case keyAddress:
					return proto.Marshal(signAddr)
				case keyNomineeAddresses:
					return protojson.Marshal(&pb.Accounts{Addresses: []*pb.Address{}})
				}
				return nil, nil
			},
			checkFn: func(t *testing.T, mockStub *mock.ChaincodeStub, payload []byte) {
				ac := &pb.Accounts{}
				require.NoError(t, protojson.Unmarshal(payload, ac))
				require.True(t, proto.Equal(ac, &pb.Accounts{Addresses: []*pb.Address{}}))
			},
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			mockStub, cfgBytes := common.NewMockStub(t)

			if len(testCase.cert) != 0 {
				common.SetCert(t, mockStub, testCase.cert)
			}

			mockStub.GetStateCalls(func(s string) ([]byte, error) {
				switch s {
				case "__config":
					return cfgBytes, nil
				}

				if testCase.getFn != nil {
					return testCase.getFn(s)
				}

				return nil, nil
			})

			ccAcl := cc.New()
			mockStub.GetFunctionAndParametersReturns(testCase.fn, testCase.args)
			resp := ccAcl.Invoke(mockStub)

			require.Equal(t, testCase.respStatus, resp.Status)
			require.Contains(t, resp.Message, testCase.errorMsg)

			if resp.Status != int32(shim.OK) {
				return
			}

			if testCase.checkFn != nil {
				testCase.checkFn(t, mockStub, resp.GetPayload())
			}
		})
	}
}
