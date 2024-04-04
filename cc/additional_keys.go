//nolint:funlen
package cc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/pkg/errors"
	"gitlab.n-t.io/core/library/chaincode/acl/cc/compositekey"
	pb "gitlab.n-t.io/core/library/go/foundation/v3/proto"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

/*
Описание хранения и обработки дополнительных ключей:

Хранение ключей:
 1. Ключи хранятся в стейте Hyperledger Fabric с использованием композитных ключей.
 2. Каждый дополнительный ключ ассоциируется с основным адресом аккаунта пользователя.
 3. Хранение выполняется в двух направлениях:
    a. 'additional_key_parent' + <дополнительный публичный ключ> -> <адрес пользователя>,
       для обратного поиска родительского адреса по дополнительному ключу.
 4. Структуры хранятся в формате protobuf, что обеспечивает согласованность с остальным кодом.

Обработка ключей:
 1. Добавление ключа включает в себя проверку формата нового ключа, проверку на уникальность и
    ассоциацию с основным адресом пользователя.
 2. Удаление ключа требует проверки, что ключ действительно связан с данным пользователем, и удаление его
    из всех связанных структур.
 3. Попытка проверки дополнительного ключа возвращает информацию о пользователе и его адресе, если ключ
    является дополнительным для какого-либо аккаунта.

Примечание:
  - Механизмы мультиподписи не используются и вместо этого проводится проверка подписей валидаторов.
  - Метод tryCheckAdditionalKey возвращает данные в формате protobuf для совместимости с методом
    CheckKeys.
*/

// AddAdditionalKey добавлет новый дополнительный публичный ключ учетной записи пользователя.
// Связывает новый ключ с "родительским" адресом пользователя в ACL.
//
// Аргументы вызова:
//   - arg[0]  - адрес пользователя для "линковки" дополнительного ключа
//   - arg[1]  - дополниельный ключ в формате base58 для добавления к аккаунту
//   - arg[2]  - JSON массив строк тегов к ключу
//   - arg[3]  - значение nonce в формате строки
//   - arg[4:] - публичные ключи и подписи валидаторов
func (c *ACL) AddAdditionalKey(
	stub shim.ChaincodeStubInterface,
	args []string,
) peer.Response {
	const argsLen = 6

	if len(args) < argsLen {
		return errf("incorrect number of arguments: expected %d, got %d", argsLen, len(args))
	}

	// Параметры запроса.
	var (
		userAddress         = args[0]
		additionalPublicKey = args[1]
		labels              = args[2]
		nonce               = args[3]
		validatorSignatures = args[4:]
	)

	// Проверка аргументов.
	if userAddress == "" {
		return errf("request validation failed: %s", ErrEmptyAddress)
	}

	if additionalPublicKey == "" {
		return errf("request validation failed: %s", ErrEmptyPubKey)
	}

	var labelsList []string
	if err := json.Unmarshal([]byte(labels), &labelsList); err != nil {
		return errf("request validation failed: invalid labels format: %s", err)
	}

	// Проверка корректности дополнительного публичного ключа.
	if err := validateKeyFormat(additionalPublicKey); err != nil {
		return errf("validation of additional public key for %s failed: %s", userAddress, err)
	}

	// Проверка прав доступа.
	if err := c.verifyAccess(stub); err != nil {
		return errf("unauthorized access: %s", err)
	}

	// Проверка nonce.
	if err := checkNonce(stub, userAddress, nonce); err != nil {
		return errf("request validation failed: %s", err)
	}

	// Проверка подписей валидаторов.
	var (
		numSignatures          = len(validatorSignatures) / 2
		validatorKeys          = validatorSignatures[:numSignatures]
		validatorHexSignatures = validatorSignatures[numSignatures:]
	)

	// Составление сообщения для подписи.
	messageElements := []string{
		"addAdditionalKey",
		userAddress,
		additionalPublicKey,
		labels,
		nonce,
	}
	messageElements = append(messageElements, validatorKeys...)

	// Создание хеша сообщения.
	messageToSign := []byte(strings.Join(messageElements, ""))
	messageDigest := sha3.Sum256(messageToSign)

	// Сверка подписей с хешем сообщения.
	if err := c.verifyValidatorSignatures(
		messageDigest[:],
		validatorKeys,
		validatorHexSignatures,
	); err != nil {
		return errf("validation of validator signatures failed: %s", err)
	}

	// Проверка на дублирование ключа в стейте.
	parentAddress, additionalKeyParentComposite, err := c.retrieveParentAddress(stub, additionalPublicKey)
	if err != nil {
		return errf("get parent address for %s: %s", userAddress, err)
	}

	if parentAddress != "" {
		return errf(
			"additional public key (%s) for %s already added",
			additionalPublicKey,
			userAddress,
		)
	}

	// Загрузка родительского дескриптора SignedAddress по адресу пользователя.
	signedAddress, publicKeyHash, err := c.retrieveSignedAddress(stub, userAddress)
	if err != nil {
		return errf("retrieve user address for %s: %s", userAddress, err)
	}

	// Добавление публичного ключа пользователю.
	signedAddress.AdditionalKeys = append(signedAddress.AdditionalKeys, &pb.AdditionalKey{
		PublicKeyBase58: additionalPublicKey,
		Labels:          labelsList,
	})

	// Сохранение обновленой структуры родительского адреса.
	if err = c.updateSignedAddress(stub, signedAddress, publicKeyHash); err != nil {
		return errf("update user address for %s: %s", userAddress, err)
	}

	// Сохранение ссылки на родительский адрес.
	if err = stub.PutState(additionalKeyParentComposite, []byte(userAddress)); err != nil {
		return errf("put state (parent link address) for %s: %s", userAddress, err)
	}

	return shim.Success(nil)
}

// RemoveAdditionalKey удаляет дополнительный ключ из учетной записи пользователя. Для случаев,
// когда ключ больше не нужен или был скомпрометирован.
//
// Аргументы вызова:
//   - arg[0]  - адрес пользователя для "отлинковки" дополнительного ключа
//   - arg[1]  - дополниельный ключ в формате base58 для удаления из аккаунта
//   - arg[2]  - значение nonce в формате строки
//   - arg[3:] - публичные ключи и подписи валидаторов
func (c *ACL) RemoveAdditionalKey(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	const argsLen = 5

	if len(args) < argsLen {
		return errf("incorrect number of arguments: expected %d, got %d", argsLen, len(args))
	}

	// Параметры запроса.
	var (
		userAddress         = args[0]
		additionalPublicKey = args[1]
		nonce               = args[2]
		validatorSignatures = args[3:]
	)

	// Проверка аргументов.
	if userAddress == "" {
		return errf("request validation failed: %s", ErrEmptyAddress)
	}

	if additionalPublicKey == "" {
		return errf("request validation failed: %s", ErrEmptyPubKey)
	}

	// Проверка валидности ключа.
	if err := validateKeyFormat(additionalPublicKey); err != nil {
		return errf("validate additional public key for %s: %s", userAddress, err)
	}

	// Проверка прав доступа.
	if err := c.verifyAccess(stub); err != nil {
		return errf(ErrUnauthorizedMsg, err)
	}

	// Проверка nonce.
	if err := checkNonce(stub, userAddress, nonce); err != nil {
		return errf("request validation failed: %s", err)
	}

	// Проверка подписей валидаторов.
	var (
		numSignatures          = len(validatorSignatures) / 2
		validatorKeys          = validatorSignatures[:numSignatures]
		validatorHexSignatures = validatorSignatures[numSignatures:]
	)

	// Составление сообщения для подписи.
	messageElements := []string{
		"removeAdditionalKey",
		userAddress,
		additionalPublicKey,
		nonce,
	}
	messageElements = append(messageElements, validatorKeys...)

	// Создание хеша сообщения.
	messageToSign := []byte(strings.Join(messageElements, ""))
	messageDigest := sha3.Sum256(messageToSign)

	// Сверка подписей с хешем сообщения.
	if err := c.verifyValidatorSignatures(
		messageDigest[:],
		validatorKeys,
		validatorHexSignatures,
	); err != nil {
		return errf("validation of validator signatures failed: %s", err)
	}

	// Проверка, что у публичного ключа родитель совпадает с адресом пользователя.
	parentAddress, additionalKeyParentComposite, err := c.retrieveParentAddress(stub, additionalPublicKey)
	if err != nil {
		return errf("get parent address for %s: %s", userAddress, err)
	}

	if parentAddress == "" {
		return errf(
			"additional public key's (%s) parent %s not found",
			additionalPublicKey,
			userAddress,
		)
	}

	if parentAddress != userAddress {
		return errf(
			"additional public key's parent address %s doesn't match with argument %s",
			parentAddress,
			userAddress,
		)
	}

	// Загрузка родительского дескриптора SignedAddress по адресу пользователя.
	signedAddress, publicKeyHash, err := c.retrieveSignedAddress(stub, userAddress)
	if err != nil {
		return errf("retrieve user address for %s: %s", userAddress, err)
	}

	// Удаление публичного ключа пользователя.
	additionalKeys := make([]*pb.AdditionalKey, 0, len(signedAddress.AdditionalKeys))
	for _, additionalKey := range signedAddress.AdditionalKeys {
		if additionalKey.PublicKeyBase58 == additionalPublicKey {
			continue
		}
		additionalKeys = append(additionalKeys, additionalKey)
	}

	if len(additionalKeys) == 0 {
		signedAddress.AdditionalKeys = nil
	} else {
		signedAddress.AdditionalKeys = additionalKeys
	}

	// Сохранение обновленой структуры родительского адреса.
	if err = c.updateSignedAddress(stub, signedAddress, publicKeyHash); err != nil {
		return errf("update user address for %s: %s", userAddress, err)
	}

	// Удаление ссылки на родительский адрес.
	if err = stub.DelState(additionalKeyParentComposite); err != nil {
		return errf("delete state (parent link address) for %s: %s", userAddress, err)
	}

	return shim.Success(nil)
}

func (c *ACL) tryCheckAdditionalKey(
	stub shim.ChaincodeStubInterface,
	args []string,
) (resp peer.Response, ok bool) {
	const (
		argsLen            = 1
		multisignSeparator = "/"
	)

	// Проверка, что аргумент единственный необходимый для случая дополнительного ключа.
	if len(args) != argsLen {
		return resp, false
	}

	// Параметры запроса.
	publicKey := args[0]

	// Проврека, является ли аргумент мультиподписью.
	if strings.Count(publicKey, multisignSeparator) > 0 {
		return resp, false
	}

	// Попытка получить адрес пользователя по дополнительному публичному ключу.
	parentAddress, _, err := c.retrieveParentAddress(stub, publicKey)
	if err != nil {
		return errf("get parent address for %s: %s", publicKey, err), true
	}

	// Если родитель не найден, то ключ обычный и управление передается вышестоящему обработчику.
	if parentAddress == "" {
		return resp, false
	}

	// Получение информации о пользователе по его дополнительному ключу.
	signedAddress, _, err := c.retrieveSignedAddress(stub, parentAddress)
	if err != nil {
		return errf("get parent signed address for %s: %s", parentAddress, err), true
	}

	accountInfo, err := getAccountInfo(stub, signedAddress.Address.AddrString())
	if err != nil {
		return errf("get account info for %s: %s", parentAddress, err), true
	}

	response, err := proto.Marshal(&pb.AclResponse{
		Account: accountInfo,
		Address: signedAddress,
	})
	if err != nil {
		return errf("marshal response for %s: %s", parentAddress, err), true
	}

	return shim.Success(response), true
}

func (c *ACL) retrieveParentAddress(
	stub shim.ChaincodeStubInterface,
	publicKeyBase58 string,
) (parentAddress string, compositeKey string, err error) {
	parentCompositeKey, err := compositekey.AdditionalKeyParent(stub, publicKeyBase58)
	if err != nil {
		return "", "", err
	}

	rawParentAddress, err := stub.GetState(parentCompositeKey)
	if err != nil {
		return "", "", err
	}

	return string(rawParentAddress), parentCompositeKey, nil
}

// validateKeyFormat decode public key from base58 to ed25519 byte array
func validateKeyFormat(encodedBase58PublicKey string) error {
	const publicKeySizeGOST = 64

	if len(encodedBase58PublicKey) == 0 {
		return errors.New("encoded base 58 public key is empty")
	}

	decode := base58.Decode(encodedBase58PublicKey)
	if len(decode) != publicKeySizeGOST && len(decode) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"incorrect decoded from base58 public key len '%s'. "+
				"decoded public key len is %d but expected %d or %d",
			encodedBase58PublicKey, len(decode),
			publicKeySizeGOST,
			ed25519.PublicKeySize,
		)
	}

	return nil
}

func errf(format string, a ...any) peer.Response {
	return shim.Error(fmt.Sprintf(format, a...))
}
