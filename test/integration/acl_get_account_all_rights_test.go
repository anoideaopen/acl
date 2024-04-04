package integration

import (
	"context"
	"os"
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	utils "gitlab.n-t.io/core/library/go/atomyze-util"
	pb "gitlab.n-t.io/core/library/go/foundation/v3/proto"
)

func TestGetAccountAllRights(t *testing.T) { //nolint:dupl
	runner.Run(t, "Get account all rghts user for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for GetAccountAllRights method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "addRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountAllRightsCheck(ctx, t, user)

		t.WithNewStep("Remove rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "removeRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountAllRightsCheckRemove(ctx, t, user)
	})
}

func getAccountAllRightsCheck(ctx context.Context, t provider.T, user utils.User) {
	t.WithNewStep("Checking user rights for added user of chaincode `acl` by getAccountAllRights", func(sCtx provider.StepCtx) {
		resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "getAccountAllRights", nil, user.UserAddressBase58Check)
		sCtx.Assert().NoError(err)

		response := &pb.AccountRights{}
		sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
		sCtx.Assert().NotNil(response.Address, "check address not nil")
		sCtx.Assert().NotNil(response.Rights, "check rights not nil")
		sCtx.Assert().Equal(user.UserAddressBase58Check, response.Address.AddrString(), "check address")
		sCtx.Assert().Len(response.Rights, 1, "check rights len")
		sCtx.Assert().Equal(channelName, response.Rights[0].ChannelName, "check chaincodeName")
		sCtx.Assert().Equal(chaincodeName, response.Rights[0].ChaincodeName, "check chaincodeName")
		sCtx.Assert().Equal(roleName, response.Rights[0].RoleName, "check roleName")
		sCtx.Assert().Equal(operationName, response.Rights[0].OperationName, "check operationName")
		sCtx.Assert().Equal(user.UserAddressBase58Check, response.Rights[0].Address.AddrString(), "check address from rights")
		sCtx.Assert().NotNil(response.Rights[0].HaveRight, "check HaveRight not nil")
		sCtx.Assert().Equal(true, response.Rights[0].HaveRight.HaveRight, "check right was added")
	})
}
