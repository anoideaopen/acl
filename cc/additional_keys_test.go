package cc

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/assert"
	pb "gitlab.n-t.io/core/library/go/foundation/v3/proto"
	"golang.org/x/crypto/sha3"
)

func TestAdditionalKeyManagement(t *testing.T) {
	var (
		stub     = StubCreate(t)
		response peer.Response
		tags     = `["tag1", "tag2", "tag3"]`
		now      = int(time.Now().UTC().Unix()) * 1000
	)
	const additionalPublicKey = "4PEK3x3CZZtQC9AJtqCVt5RFJgjt5s6PqS7JL7cCboBfYJMiufaMFo4YCp7gKUQ8AXGM5Wb9i15617SS7hhr3P7M"

	// Создание пользователя.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(fnAddUser),
			[]byte(pubkey),
			[]byte(kycHash),
			[]byte(testUserID),
			[]byte("true"),
		},
	)
	assert.Equal(t, int32(shim.OK), response.Status)

	// Проверка ключа пользователя.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(fnCheckKeys),
			[]byte(pubkey),
		},
	)
	assert.Equal(t, int32(shim.OK), response.Status)

	// Получение адреса пользователя.
	var userInfo pb.AclResponse
	assert.NoError(t, proto.Unmarshal(response.Payload, &userInfo))

	userAddress := userInfo.Address.Address.AddrString()

	validatorPublicKeys := make([]string, 0, len(MockValidatorKeys))
	for publicKey := range MockValidatorKeys {
		validatorPublicKeys = append(validatorPublicKeys, publicKey)
	}

	nonce := strconv.Itoa(now)

	// Составление сообщения для подписи.
	messageElements := []string{
		"addAdditionalKey",
		userAddress,
		additionalPublicKey,
		tags,
		nonce,
	}
	messageElements = append(messageElements, validatorPublicKeys...)

	// Создание хеша сообщения.
	messageToSign := []byte(strings.Join(messageElements, ""))
	messageDigest := sha3.Sum256(messageToSign)

	// Подписывание сообщения.
	validatorKeys, validatorSignatures := generateTestValidatorSignatures(validatorPublicKeys, messageDigest[:])

	// Добавление дополнительного ключа пользователя.
	args := [][]byte{
		[]byte(fnAddAdditionalKey),
		[]byte(userAddress),
		[]byte(additionalPublicKey),
		[]byte(tags),
		[]byte(nonce),
	}
	args = append(args, validatorKeys...)
	args = append(args, validatorSignatures...)

	response = stub.MockInvoke("0", args)
	assert.Equal(t, int32(shim.OK), response.Status)

	// Повторное добавление дополнительного ключа пользователя.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(fnAddAdditionalKey),
			[]byte(userAddress),
			[]byte(additionalPublicKey),
			[]byte(tags),
		},
	)
	assert.Equal(t, int32(shim.ERROR), response.Status)

	// Проверка наличия дополнительного ключа пользователя.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(fnCheckKeys),
			[]byte(additionalPublicKey),
		},
	)
	assert.NoError(t, proto.Unmarshal(response.Payload, &userInfo))
	assert.Equal(t, userAddress, userInfo.Address.Address.AddrString())
	assert.Equal(t, additionalPublicKey, userInfo.Address.AdditionalKeys[0].PublicKeyBase58)
	assert.Len(t, userInfo.Address.AdditionalKeys[0].Labels, 3)

	// Получение информации об аккаунте по адресу.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(fnGetUser),
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

	// Составление сообщения для подписи.
	messageElements = []string{
		"removeAdditionalKey",
		userAddress,
		additionalPublicKey,
		nonce,
	}
	messageElements = append(messageElements, validatorPublicKeys...)

	// Создание хеша сообщения.
	messageToSign = []byte(strings.Join(messageElements, ""))
	messageDigest = sha3.Sum256(messageToSign)

	// Подписывание сообщения.
	validatorKeys, validatorSignatures = generateTestValidatorSignatures(validatorPublicKeys, messageDigest[:])

	// Удаление дополнительного ключа.
	args = [][]byte{
		[]byte(fnRemoveAdditionalKey),
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
			[]byte(fnCheckKeys),
			[]byte(additionalPublicKey),
		},
	)
	assert.Equal(t, int32(shim.ERROR), response.Status)

	// Проверка основного ключа.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(fnCheckKeys),
			[]byte(pubkey),
		},
	)
	assert.Equal(t, int32(shim.OK), response.Status)

	// Получение информации об аккаунте по адресу.
	response = stub.MockInvoke(
		"0",
		[][]byte{
			[]byte(fnGetUser),
			[]byte(userAddress),
		},
	)

	assert.Equal(t, int32(shim.OK), response.Status)
	assert.NoError(t, proto.Unmarshal(response.Payload, &signedAddress))
	assert.Nil(t, signedAddress.AdditionalKeys)
}
