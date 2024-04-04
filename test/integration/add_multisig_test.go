package integration

import (
	"os"
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	utils "gitlab.n-t.io/core/library/go/atomyze-util"
)

// TestAddMultisig - adding 2 users and creating multisig
func TestAddMultisig(t *testing.T) {
	runner.Run(t, "adding 2 users and creating multisig", func(t provider.T) {
		t.Severity(allure.BLOCKER)
		t.Description("adding 2 users and creating multisig")
		t.Tags("acl", "positive")
		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user1 := utils.AddUser(t, *hlfProxy)
		user2 := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Creating multisig", func(sCtx provider.StepCtx) {
			emitArgs := []string{"2"}
			signedEmitArgs, err := utils.MultisigHex("addMultisig", emitArgs, user1, user2)
			sCtx.Require().NoError(err)
			_, err = hlfProxy.Invoke("acl", "addMultisig", signedEmitArgs...)
			sCtx.Require().NoError(err)
		})
	})
}
