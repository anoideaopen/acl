package integration

import (
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
)

// TestChangePublicKeyBase58 - change first public key with the second public key with base58 signature and check that we get the old address using the new key
func TestChangePublicKeyBase58(t *testing.T) {
	runner.Run(t, "Change first public key with the second public key with base58 signature and check that we get the old address using the new key", func(t provider.T) {
		t.Severity(allure.BLOCKER)
		t.Description("Change first public key with the second public key with base58 signature and check that we get the old address using the new key")
		t.Tags("acl", "positive")

		// hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))
		//
		// issuer := utils.AddIssuer(t, *hlfProxy, os.Getenv(utils.FiatIssuerPrivateKey))
		// user1 := utils.AddUser(t, *hlfProxy)
		// user2 := utils.AddUser(t, *hlfProxy)

		// t.WithNewStep("Change public key", func(sCtx provider.StepCtx) {
		// 	args := []string{user1.UserAddressBase58Check, defaultReason, reasonID, user2.UserPublicKeyBase58}
		// 	signedArgs, err := utils.Sign(issuer.IssuerEd25519PrivateKey, issuer.IssuerEd25519PublicKey, "acl", "acl", "changePublicKeyWithBase58Signature", args)
		// 	sCtx.Require().NoError(err)
		// 	resp, err := hlfProxy.Invoke("acl", "changePublicKeyWithBase58Signature", signedArgs...)
		// 	sCtx.Require().NoError(err)
		// 	t.Log(resp.Payload)
		//
		// 	time.Sleep(utils.BatchTransactionTimeout)
		// 	t.WithNewStep("Check that we get the old address using the new key", func(sCtx provider.StepCtx) {
		// 		resp, err = hlfProxy.Query("acl", "checkKeys", user2.UserPublicKeyBase58)
		// 		sCtx.Assert().NoError(err)
		//
		// 		response := &pb.AclResponse{}
		// 		err = proto.Unmarshal(resp.Payload, response)
		// 		sCtx.Require().NoError(err)
		// 		sCtx.Assert().Equal(user1.UserAddressBase58Check, response.Address.Address.AddrString())
		// 	})
		// })
	})
}
