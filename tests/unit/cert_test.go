package unit

import (
	"testing"

	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/tests/common"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
)

func TestCert(t *testing.T) {
	stub := common.StubCreateAndInit(t)

	t.Run("use no cert", func(t *testing.T) {
		stub.Creator = []byte{}
		resp := stub.MockInvoke("0", [][]byte{[]byte(common.FnAddUser), []byte(common.PubKey), []byte(common.TestAddr)})
		require.Equal(t, int32(shim.ERROR), resp.Status)
	})

	t.Run("use invalid cert", func(t *testing.T) {
		cert, err := common.GetCert(common.UserCertPath)
		require.NoError(t, err)
		require.NotNil(t, cert)

		err = common.SetCreator(stub, common.TestCreatorMSP, cert.Raw)
		require.NoError(t, err)

		resp := stub.MockInvoke("0", [][]byte{
			[]byte(common.FnAddUser),
			[]byte(common.PubKey),
			[]byte(kycHash),
			[]byte(testUserID),
			[]byte(stateTrue),
		})
		require.Equal(t, int32(shim.ERROR), resp.Status)
		require.Equal(t, resp.Message, "unauthorized: "+errs.ErrCallerNotAdmin)
	})

	t.Run("use valid cert", func(t *testing.T) {
		cert, err := common.GetCert(common.AdminCertPath)
		require.NoError(t, err)
		err = common.SetCreator(stub, common.TestCreatorMSP, cert.Raw)
		require.NoError(t, err)

		resp := stub.MockInvoke("0", [][]byte{
			[]byte(common.FnAddUser), []byte(common.PubKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue),
		})
		require.Equal(t, int32(shim.OK), resp.Status, resp.Message)
	})
}
