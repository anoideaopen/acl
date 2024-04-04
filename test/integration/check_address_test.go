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

// TestCheckAddress adding user and checking address with CheckAddress function
// then adding user to gray list and checking that checkAddress returns an error
func TestCheckAddress(t *testing.T) {
	runner.Run(t, "Check address test", func(t provider.T) {
		t.Severity(allure.BLOCKER)
		t.Description("Check address test")
		t.Tags("acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))
		user := utils.AddUser(t, *hlfProxy)
		userID := "testuser"
		isIndustrial := true
		isMultisig := false

		t.WithNewStep("Check address with check CheckAddress function", func(sCtx provider.StepCtx) {
			r, err := hlfProxy.Invoke("acl", "checkAddress", user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)

			a := &pb.Address{}
			err = proto.Unmarshal(r.Payload, a)
			sCtx.Assert().NoError(err)

			sCtx.Assert().Equal(user.UserAddressBase58Check, a.AddrString(),
				"checking that userAddress is equal %s", user.UserAddressBase58Check)
			sCtx.Assert().Equal(userID, a.UserID, "checking that userID is equal %s ", userID)
			sCtx.Assert().Equal(true, a.IsIndustrial, "checking that isIndustrial is equal %s", isIndustrial)
			sCtx.Assert().Equal(false, a.IsMultisig, "checking that isMultisig is equal %s", isMultisig)
		})

		t.WithNewStep("Add user to grey list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "addToList", user.UserAddressBase58Check, "gray")
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Check address with check CheckAddress function when user graylisted", func(sCtx provider.StepCtx) {
			r, err := hlfProxy.Invoke("acl", "checkAddress", user.UserAddressBase58Check)
			sCtx.Assert().Contains(err.Error(), user.UserAddressBase58Check+" is graylisted",
				"checking that checkAddress returns an error when user graylisted")
			sCtx.Assert().Nil(r)
		})
	})
}
