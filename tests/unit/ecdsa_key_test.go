package unit

import (
	"testing"

	"github.com/anoideaopen/acl/tests/common"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

func TestAddUserECDSAPublicKey(t *testing.T) {
	t.Parallel()

	const (
		testKeyECDSA = "3VeCgHy4GFyMGW26sfc797eUUPHBtmngT4t4E2tx87d627JMmrBcsUgKnaDBtozuRp4Hvr1VUc7E8niMFfDdU9JG"
		testAddress  = "2gNhUTgbNJEqnwFfrWLpdtQeGj2hxVz7d3VgzNJBHjpPpDhMVo"
	)

	stub := common.StubCreateAndInit(t)

	t.Run("[negative] add user with wrong key length", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     testKeyECDSA,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeEd25519,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "unexpected key length",
		}

		resp := addUser(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})

	t.Run("add user with ecdsa key", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     testKeyECDSA,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeECDSA,
			respStatus:     int32(shim.OK),
			errorMsg:       "",
		}

		resp := addUserWithPublicKeyType(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})

	t.Run("[negative] add user with ecdsa key again", func(t *testing.T) {
		s := &seriesAddUser{
			testPubKey:     testKeyECDSA,
			testAddress:    testAddress,
			kycHash:        kycHash,
			testUserID:     testUserID,
			testPubKeyType: common.KeyTypeECDSA,
			respStatus:     int32(shim.ERROR),
			errorMsg:       "already exists",
		}

		resp := addUserWithPublicKeyType(stub, s)
		validationResultAddUser(t, stub, resp, s)
	})
}
