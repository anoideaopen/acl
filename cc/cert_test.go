package cc

import (
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/assert"
)

func TestCert(t *testing.T) {
	stub := StubCreate(t)

	t.Run("use no cert", func(t *testing.T) {
		stub.Creator = []byte{}
		resp := stub.MockInvoke("0", [][]byte{[]byte(fnAddUser), []byte(pubkey), []byte(testaddr)})
		assert.Equal(t, int32(shim.ERROR), resp.Status)
	})

	t.Run("use invalid cert", func(t *testing.T) {
		cert, err := getCert(userCertPath)
		assert.NoError(t, err)
		assert.NotNil(t, cert)

		err = SetCreator(stub, testCreatorMSP, cert.Raw)
		assert.NoError(t, err)

		resp := stub.MockInvoke("0", [][]byte{
			[]byte(fnAddUser),
			[]byte(pubkey),
			[]byte(kycHash),
			[]byte(testUserID),
			[]byte(stateTrue),
		})
		assert.Equal(t, int32(shim.ERROR), resp.Status)
		assert.Equal(t, resp.Message, "unauthorized: "+ErrCallerNotAdmin)
	})

	t.Run("use valid cert", func(t *testing.T) {
		cert, err := getCert(adminCertPath)
		assert.NoError(t, err)
		err = SetCreator(stub, testCreatorMSP, cert.Raw)
		assert.NoError(t, err)

		resp := stub.MockInvoke("0", [][]byte{
			[]byte(fnAddUser), []byte(pubkey), []byte(kycHash), []byte(testUserID), []byte(stateTrue),
		})
		assert.Equal(t, int32(shim.OK), resp.Status, resp.Message)
	})
}
