package integration

import (
	"os"
	"testing"
	"time"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	utils "gitlab.n-t.io/core/library/go/atomyze-util"
	pb "gitlab.n-t.io/core/library/go/foundation/v3/proto"
	"google.golang.org/protobuf/proto"
)

const (
	defaultReason = "because..."
	reasonID      = "1"
)

// TestChangePublicKey - change first public key with the second public key with hex signature;
// check that public key was changed but the address is not changed (from previous public key)
func TestChangePublicKey(t *testing.T) {
	runner.Run(t, "Change public key with new one", func(t provider.T) {
		t.Severity(allure.BLOCKER)
		t.Description("change first public key with the second public key with hex signature; " +
			"check that public key was changed but the address is not changed (from previous public key)")
		t.Tags("acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		issuer := utils.AddIssuer(t, *hlfProxy, os.Getenv(utils.FiatIssuerPrivateKey))
		user1 := utils.AddUser(t, *hlfProxy)
		user2 := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Change public key", func(sCtx provider.StepCtx) {
			args := []string{
				user1.UserAddressBase58Check,
				defaultReason,
				reasonID,
				user2.UserPublicKeyBase58,
			}
			signedArgs, err := utils.SignHex(
				issuer.IssuerEd25519PrivateKey,
				issuer.IssuerEd25519PublicKey,
				"changePublicKey",
				args,
			)
			sCtx.Require().NoError(err)
			resp, err := hlfProxy.Invoke("acl", "changePublicKey", signedArgs...)
			sCtx.Require().NoError(err)
			t.Log(resp.Payload)

			time.Sleep(utils.BatchTransactionTimeout)
			t.WithNewStep("Check that we get the old address using the new key",
				func(sCtx provider.StepCtx) {
					resp, err := hlfProxy.Query("acl", "checkKeys", user2.UserPublicKeyBase58)
					sCtx.Assert().NoError(err)

					response := &pb.AclResponse{}
					err = proto.Unmarshal(resp.Payload, response)
					sCtx.Require().NoError(err)
					// address is the same it, but the public key was changed to user2.UserPublicKeyBase58
					sCtx.Assert().Equal(user1.UserAddressBase58Check, response.Address.Address.AddrString())
				})
		})
	})
}
