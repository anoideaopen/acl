package integration

import (
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
)

func TestGetAccountInfo(t *testing.T) {
	runner.Run(t, "get account info for acl chaincode", func(t provider.T) {
		// ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for GetAccountInfo method for ACL ")
		t.Tags("integration", "acl", "positive")

		// hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))
		//
		// user := utils.AddUser(t, *hlfProxy)
		//
		// t.WithNewStep("Set account info for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
		// 	_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
		// 		os.Getenv(utils.HlfProxyAuthToken), "acl", "setAccountInfo", nil, user.UserAddressBase58Check, newKycHash, "false", "false")
		// 	sCtx.Assert().NoError(err)
		// })

		// t.WithNewStep("Get account info for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
		// 	resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
		// 		os.Getenv(utils.HlfProxyAuthToken), "acl", "getAccountInfo", nil, user.UserAddressBase58Check)
		// 	sCtx.Assert().NoError(err)
		//
		// 	addrFromLedger := &pb.AccountInfo{}
		// 	sCtx.Assert().NoError(json.Unmarshal(resp.Payload, addrFromLedger))
		// 	sCtx.Assert().Equal(newKycHash, addrFromLedger.KycHash, "check new kycHash")
		// 	sCtx.Assert().Equal(false, addrFromLedger.GrayListed, "check graylisted state")
		// 	sCtx.Assert().Equal(false, addrFromLedger.BlackListed, "check blacklisted state")
		// })
	})
}
