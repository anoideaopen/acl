package tests

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func TestAdditionalKeyManagement(t *testing.T) {
	var (
		stub     = common.StubCreateAndInit(t)
		response peer.Response
		tags     = `["tag1", "tag2", "tag3"]`
		now      = int(time.Now().UTC().Unix()) * 1000
	)
	const additionalPublicKey = "4PEK3x3CZZtQC9AJtqCVt5RFJgjt5s6PqS7JL7cCboBfYJMiufaMFo4YCp7gKUQ8AXGM5Wb9i15617SS7hhr3P7M"

	// User Creation.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(common.FnAddUser),
			[]byte(common.PubKey),
			[]byte(kycHash),
			[]byte(testUserID),
			[]byte("true"),
		},
	)
	assert.Equal(t, int32(shim.OK), response.Status)

	// User Key Verification.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(common.FnCheckKeys),
			[]byte(common.PubKey),
		},
	)
	assert.Equal(t, int32(shim.OK), response.Status)

	// Getting the user's address.
	var userInfo pb.AclResponse
	assert.NoError(t, proto.Unmarshal(response.Payload, &userInfo))

	userAddress := userInfo.Address.Address.AddrString()

	validatorPublicKeys := make([]string, 0, len(common.MockValidatorKeys))
	for publicKey := range common.MockValidatorKeys {
		validatorPublicKeys = append(validatorPublicKeys, publicKey)
	}

	nonce := strconv.Itoa(now)

	// Composing a message to be signed.
	messageElements := []string{
		"addAdditionalKey",
		userAddress,
		additionalPublicKey,
		tags,
		nonce,
	}
	messageElements = append(messageElements, validatorPublicKeys...)

	// Creating a hash of the message.
	messageToSign := []byte(strings.Join(messageElements, ""))
	messageDigest := sha3.Sum256(messageToSign)

	// Signing the message.
	validatorKeys, validatorSignatures := common.GenerateTestValidatorSignatures(validatorPublicKeys, messageDigest[:])

	// Appending an additional user key.
	args := [][]byte{
		[]byte(common.FnAddAdditionalKey),
		[]byte(userAddress),
		[]byte(additionalPublicKey),
		[]byte(tags),
		[]byte(nonce),
	}
	args = append(args, validatorKeys...)
	args = append(args, validatorSignatures...)

	response = stub.MockInvoke("0", args)
	assert.Equal(t, int32(shim.OK), response.Status)

	// Re-add an additional user key.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(common.FnAddAdditionalKey),
			[]byte(userAddress),
			[]byte(additionalPublicKey),
			[]byte(tags),
		},
	)
	assert.Equal(t, int32(shim.ERROR), response.Status)

	// Checking for the presence of an additional user key.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(common.FnCheckKeys),
			[]byte(additionalPublicKey),
		},
	)
	assert.NoError(t, proto.Unmarshal(response.Payload, &userInfo))
	assert.Equal(t, userAddress, userInfo.Address.Address.AddrString())
	assert.Equal(t, additionalPublicKey, userInfo.Address.AdditionalKeys[0].PublicKeyBase58)
	assert.Len(t, userInfo.Address.AdditionalKeys[0].Labels, 3)

	// Obtaining account information at.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(common.FnGetUser),
			[]byte(userAddress),
		},
	)

	var signedAddress pb.SignedAddress
	assert.Equal(t, int32(shim.OK), response.Status)
	assert.NoError(t, proto.Unmarshal(response.Payload, &signedAddress))
	assert.Equal(t, userAddress, signedAddress.Address.AddrString())
	assert.Equal(t, additionalPublicKey, signedAddress.AdditionalKeys[0].PublicKeyBase58)
	assert.Len(t, signedAddress.AdditionalKeys[0].Labels, 3)

	now++
	nonce = strconv.Itoa(now)

	// Composing a message to be signed.
	messageElements = []string{
		"removeAdditionalKey",
		userAddress,
		additionalPublicKey,
		nonce,
	}
	messageElements = append(messageElements, validatorPublicKeys...)

	// Creating a hash of the message.
	messageToSign = []byte(strings.Join(messageElements, ""))
	messageDigest = sha3.Sum256(messageToSign)

	// Signing the message.
	validatorKeys, validatorSignatures = common.GenerateTestValidatorSignatures(validatorPublicKeys, messageDigest[:])

	// Removal of an additional key.
	args = [][]byte{
		[]byte(common.FnRemoveAdditionalKey),
		[]byte(userAddress),
		[]byte(additionalPublicKey),
		[]byte(nonce),
	}
	args = append(args, validatorKeys...)
	args = append(args, validatorSignatures...)

	response = stub.MockInvoke("0", args)
	assert.Equal(t, int32(shim.OK), response.Status)

	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(common.FnCheckKeys),
			[]byte(additionalPublicKey),
		},
	)
	assert.Equal(t, int32(shim.ERROR), response.Status)

	// Verification of the primary key.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(common.FnCheckKeys),
			[]byte(common.PubKey),
		},
	)
	assert.Equal(t, int32(shim.OK), response.Status)

	// Obtaining account information at.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(common.FnGetUser),
			[]byte(userAddress),
		},
	)

	assert.Equal(t, int32(shim.OK), response.Status)
	assert.NoError(t, proto.Unmarshal(response.Payload, &signedAddress))
	assert.Nil(t, signedAddress.AdditionalKeys)
}
