package integration

import (
	"os"
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	utils "gitlab.n-t.io/core/library/go/atomyze-util"
)

// TestGetAddresses - add three users and get their addresses with getAddresses function
func TestGetAddresses(t *testing.T) {
	runner.Run(t, "add three users and get their addresses with getAddresses function", func(t provider.T) {
		t.Severity(allure.BLOCKER)
		t.Description("add three users and get their addresses with getAddresses function")
		t.Tags("acl", "positive")
		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user1 := utils.AddUser(t, *hlfProxy)
		user2 := utils.AddUser(t, *hlfProxy)
		user3 := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("get addresses and check that they contains user1 user2 and user3", func(sCtx provider.StepCtx) {
			r, err := hlfProxy.Invoke("acl", "getAddresses", "100000", "")
			sCtx.Assert().NoError(err)

			s := string(r.Payload)
			sCtx.Assert().Contains(s, user1.UserAddressBase58Check)
			sCtx.Assert().Contains(s, user2.UserAddressBase58Check)
			sCtx.Assert().Contains(s, user3.UserAddressBase58Check)
		})
	})
}
