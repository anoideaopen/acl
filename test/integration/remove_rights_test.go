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

func TestRemoveRights(t *testing.T) {
	runner.Run(t, "remove rights user for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for RemoveRights method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		addRightsAndCheck(ctx, t, user)

		t.WithNewStep("Remove rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "removeRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountOperationRightCheckRemove(ctx, t, user)
		getAccountAllRightsCheckRemove(ctx, t, user)
		getOperationAllRightsCheckRemove(ctx, t)
	})
}

func TestRemoveRightsAgain(t *testing.T) {
	runner.Run(t, "remove rights again for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for RemoveRights method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		addRightsAndCheck(ctx, t, user)

		t.WithNewStep("Remove rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "removeRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountOperationRightCheckRemove(ctx, t, user)

		t.WithNewStep("Remove rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "removeRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountOperationRightCheckRemove(ctx, t, user)
		getAccountAllRightsCheckRemove(ctx, t, user)
	})
}

func addRightsAndCheck(ctx context.Context, t provider.T, user utils.User) {
	t.WithNewStep("Add rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
		_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "addRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
		sCtx.Assert().NoError(err)
	})

	getAccountOperationRightCheck(ctx, t, user)
	getAccountAllRightsCheck(ctx, t, user)
}

func getAccountOperationRightCheckRemove(ctx context.Context, t provider.T, user utils.User) {
	t.WithNewStep("Checking right after remove for added user of chaincode `acl` by getAccountOperationRight", func(sCtx provider.StepCtx) {
		resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "getAccountOperationRight", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
		sCtx.Assert().NoError(err)

		response := &pb.HaveRight{}
		sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
		sCtx.Assert().NotNil(response.HaveRight, "check HaveRight not nil")
		sCtx.Assert().Equal(false, response.HaveRight, "check right was added")
	})
}

func getAccountAllRightsCheckRemove(ctx context.Context, t provider.T, user utils.User) {
	t.WithNewStep("Checking user rights after remove for added user of chaincode `acl` by getAccountAllRights", func(sCtx provider.StepCtx) {
		resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "getAccountAllRights", nil, user.UserAddressBase58Check)
		sCtx.Assert().NoError(err)

		response := &pb.AccountRights{}
		sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
		sCtx.Assert().NotNil(response.Address, "check address not nil")
		sCtx.Assert().Nil(response.Rights, "check rights equal nil")
		sCtx.Assert().Equal(user.UserAddressBase58Check, response.Address.AddrString(), "check address")
		sCtx.Assert().Len(response.Rights, 0, "check rights len")
	})
}
