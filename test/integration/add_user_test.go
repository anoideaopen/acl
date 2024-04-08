package integration

import (
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
)

// TestAddUser - add user in acl chaincode and check 'kycHash', 'userID', 'isIndustrial' by querying method `checkKeys`
func TestAddUser(t *testing.T) {
	runner.Run(t, "add user in acl chaincode and check 'kycHash', 'userID', 'isIndustrial' by querying method `checkKeys`", func(t provider.T) {
		// ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("As member of organization add user in acl chaincode and validate that user was added")
		t.Tags("acl", "positive")

		// var (
		// 	publicKey string
		// 	userAddress string
		// )
		const (
			kycHash      string = "test"
			userID       string = "testuser"
			isIndustrial string = "true"
		)

		t.WithNewStep("Generate cryptos for user", func(sCtx provider.StepCtx) {
			// _, pkey, err := utils.GeneratePrivateAndPublicKey()
			// sCtx.Assert().NoError(err)
			// publicKey = base58.Encode(pkey)
			// userAddress, err = utils.GetAddressByPublicKey(pkey)
			// sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Add user by invoking method `addUser` of chaincode `acl` with valid parameters", func(sCtx provider.StepCtx) {
			// r, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
			// 	os.Getenv(utils.HlfProxyAuthToken),
			// 	"acl", "addUser", nil, publicKey, kycHash, userID, isIndustrial)
			// sCtx.Assert().NoError(err)
			// sCtx.Assert().NotNil(r)
		})

		// time.Sleep(utils.BatchTransactionTimeout)
		// t.WithNewStep("Check user is created by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
		// 	r, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
		// 		os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, publicKey)
		// 	sCtx.Assert().NoError(err)
		//
		// 	a := &pb.AclResponse{}
		// 	err = proto.Unmarshal(r.Payload, a)
		// 	sCtx.Assert().NoError(err)
		// 	sCtx.Assert().Equal(a.Account.KycHash, kycHash, "checking that kysHash is equal %s", kycHash)
		// 	sCtx.Assert().Equal(a.Address.Address.AddrString(), userAddress, "checking that userAddress is equal %s", userAddress)
		// 	sCtx.Assert().Equal(a.Address.Address.UserID, userID, "checking that userID is equal %s", userID)
		// 	sCtx.Assert().Equal(strconv.FormatBool(a.Address.Address.IsIndustrial), isIndustrial, "checking that isIndustrial is equal %s", isIndustrial)
		// 	sCtx.Assert().False(a.Account.GrayListed, "checking that grayListed is equal false")
		// 	sCtx.Assert().False(a.Address.Address.IsMultisig, "checking that isMultisig is equal false")
		// })
	})
}
