package integration

import (
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
)

func TestCheckKeys(t *testing.T) {
	runner.Run(t, "add user in acl chaincode and ckeck by querying method `checkKeys`", func(t provider.T) {
		// ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Test for CheckKeys method for ACL ")
		t.Tags("acl", "positive")

		const (
			kycHash      string = "test"
			userID       string = "testuser"
			isIndustrial string = "true"
		)

		// hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))
		//
		// user := utils.AddUser(t, *hlfProxy)
		//
		// time.Sleep(utils.BatchTransactionTimeout)
		// t.WithNewStep("Check user is created by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
		// 	resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
		// 		os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
		// 	sCtx.Assert().NoError(err)
		//
		// 	response := &pb.AclResponse{}
		// 	err = proto.Unmarshal(resp.Payload, response)
		// 	sCtx.Assert().NoError(err)
		// 	sCtx.Assert().NotNil(response.Address)
		// 	sCtx.Assert().NotNil(response.Account)
		// 	sCtx.Assert().Equal(response.Account.KycHash, kycHash, "checking that kysHash is equal %s", kycHash)
		// 	sCtx.Assert().Equal(response.Address.Address.AddrString(), user.UserAddressBase58Check, "checking that userAddress is equal %s", user.UserAddressBase58Check)
		// 	sCtx.Assert().Equal(response.Address.Address.UserID, userID, "checking that userID is equal %s", userID)
		// 	sCtx.Assert().Equal(strconv.FormatBool(response.Address.Address.IsIndustrial), isIndustrial, "checking that isIndustrial is equal %s", isIndustrial)
		// 	sCtx.Assert().False(response.Account.GrayListed, "checking that grayListed is equal false")
		// 	sCtx.Assert().False(response.Account.BlackListed, "checking that blackListed is equal false")
		// 	sCtx.Assert().False(response.Address.Address.IsMultisig, "checking that isMultisig is equal false")
		// })
	})
}
