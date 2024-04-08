package integration

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"golang.org/x/crypto/ed25519"
)

func TestChangeMultisigPubkey(t *testing.T) {
	runner.Run(t, "adding 2 users and creating multisig then chaging multisig", func(t provider.T) {
		t.Severity(allure.BLOCKER)
		t.Description("adding 2 users and creating multisig then chaging multisig")
		t.Tags("acl", "positive")
		// hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))
		//
		// issuer := utils.AddIssuer(t, *hlfProxy, os.Getenv(utils.FiatIssuerPrivateKey))
		//
		// user1 := utils.AddUser(t, *hlfProxy)
		// user2 := utils.AddUser(t, *hlfProxy)
		// var pubKeys []string
		// pubKeys = append(pubKeys, user1.UserPublicKeyBase58)
		// pubKeys = append(pubKeys, user2.UserPublicKeyBase58)
		//
		// t.WithNewStep("adding 2 users and creating multisig then chaging multisig", func(sCtx provider.StepCtx) {
		// 	emitArgs := []string{"2"}
		// 	signedEmitArgs, err := utils.MultisigHex("addMultisig", emitArgs, user1, user2)
		// 	sCtx.Require().NoError(err)
		// 	_, err = hlfProxy.Invoke("acl", "addMultisig", signedEmitArgs...)
		// 	sCtx.Require().NoError(err)
		//
		// 	oldKey := pubKeys[0]
		// 	reason := "because..."
		// 	reasonID := "1"
		//
		// 	// derive address from hash of sorted base58-(DE)coded pubkeys
		// 	pubKeysString := strings.Join(pubKeys, "/")
		// 	keysArrSorted, err := decodeAndSort(pubKeysString)
		// 	assert.NoError(t, err)
		// 	hashedPksSortedOrder := sha3.Sum256(bytes.Join(keysArrSorted, []byte("")))
		// 	addrEncoded := base58.CheckEncode(hashedPksSortedOrder[1:], hashedPksSortedOrder[0])
		//
		// 	u := utils.AddUser(t, *hlfProxy)
		// 	newKeysString := u.UserPublicKeyBase58 + "/" + user2.UserPublicKeyBase58
		// 	signedChangeMultisigPublicKeyArgs := []string{addrEncoded, oldKey, newKeysString, reason, reasonID}
		//
		// 	nonce := utils.GetNonce()
		// 	msgWithSign, err := utils.SignHexWithNonce(issuer.IssuerEd25519PrivateKey, issuer.IssuerEd25519PublicKey, "changeMultisigPublicKey", signedChangeMultisigPublicKeyArgs, nonce)
		// 	sCtx.Require().NoError(err)
		// 	signature := msgWithSign[len(msgWithSign)-1]
		//
		// 	argsChangeMultisigPublicKey := []string{addrEncoded, oldKey, u.UserPublicKeyBase58, reason, reasonID, nonce}
		// 	argsChangeMultisigPublicKey = append(argsChangeMultisigPublicKey, utils.ConvertPublicKeyToBase58(issuer.IssuerEd25519PublicKey))
		// 	argsChangeMultisigPublicKey = append(argsChangeMultisigPublicKey, signature)
		// 	r, err := hlfProxy.Invoke("acl", "changeMultisigPublicKey", argsChangeMultisigPublicKey...)
		// 	sCtx.Require().NoError(err)
		// 	utils.CheckStatusCode(t, http.StatusOK, int(r.ChaincodeStatus))
		// })
	})
}

func decodeAndSort(item string) ([][]byte, error) {
	const delimiter = "/"
	publicKeys := strings.Split(item, delimiter)
	binKeys := make([][]byte, len(publicKeys))
	for i, encodedBase58PublicKey := range publicKeys {
		decodedPublicKey, err := decodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return nil, err
		}
		binKeys[i] = decodedPublicKey
	}
	sort.Slice(binKeys, func(i, j int) bool {
		return bytes.Compare(binKeys[i], binKeys[j]) < 0
	})
	return binKeys, nil
}

// decodeBase58PublicKey decode public key from base58 to ed25519 byte array
func decodeBase58PublicKey(encodedBase58PublicKey string) ([]byte, error) {
	if len(encodedBase58PublicKey) == 0 {
		return nil, errors.New("encoded base 58 public key is empty")
	}
	decode := base58.Decode(encodedBase58PublicKey)
	if len(decode) == 0 {
		return nil, fmt.Errorf("failed base58 decoding of key %s", encodedBase58PublicKey)
	}
	if len(decode) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("incorrect decoded from base58 public key len '%s'. "+
			"decoded public key len is %d but expected %d", encodedBase58PublicKey, len(decode), ed25519.PublicKeySize)
	}
	return decode, nil
}
