package integration

import (
	"os"
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	utils "gitlab.n-t.io/core/library/go/atomyze-util"
	pb "gitlab.n-t.io/core/library/go/foundation/v3/proto"
	"google.golang.org/protobuf/proto"
)

func TestSetkyc(t *testing.T) {
	runner.Run(t, "add user in acl chaincode and check 'kycHash', 'userID', 'isIndustrial' by querying method `checkKeys`", func(t provider.T) {
		t.Severity(allure.BLOCKER)
		t.Description("As member of organization add user in acl chaincode and validate that user was added")
		t.Tags("acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))
		issuer := utils.AddIssuer(t, *hlfProxy, os.Getenv(utils.FiatIssuerPrivateKey))
		user := utils.AddUser(t, *hlfProxy)
		newKycHash := "newtest"

		t.WithNewStep("Sign args and change kyshash", func(sCtx provider.StepCtx) {
			emitArgs := []string{user.UserAddressBase58Check, newKycHash}
			signedEmitArgs, err := utils.SignHex(issuer.IssuerEd25519PrivateKey, issuer.IssuerEd25519PublicKey, "setkyc", emitArgs)
			sCtx.Require().NoError(err)
			r, err := hlfProxy.Invoke("acl", "setkyc", signedEmitArgs...)
			sCtx.Require().NoError(err)
			sCtx.Assert().NotNil(r)
		})

		t.WithNewStep("Checking new kysHash by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			r, err := hlfProxy.Query("acl", "checkKeys", user.UserPublicKeyBase58)
			sCtx.Require().NoError(err)
			a := &pb.AclResponse{}
			err = proto.Unmarshal(r.Payload, a)
			sCtx.Require().NoError(err)
			sCtx.Require().Equal(a.Account.KycHash, newKycHash, "checking that kysHash is equal %s", newKycHash)
		})
	})
}
