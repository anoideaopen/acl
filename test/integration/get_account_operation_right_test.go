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

func TestGetAccountOperationRight(t *testing.T) { //nolint:dupl
	runner.Run(t, "get acount operation right user for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for GetAccountOperationRight method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "addRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountOperationRightCheck(ctx, t, user)

		t.WithNewStep("Remove rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "removeRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountOperationRightCheckRemove(ctx, t, user)
	})
}

func getAccountOperationRightCheck(ctx context.Context, t provider.T, user utils.User) {
	t.WithNewStep("Checking right for added user of chaincode `acl` by getAccountOperationRight", func(sCtx provider.StepCtx) {
		resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "getAccountOperationRight", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
		sCtx.Assert().NoError(err)

		response := &pb.HaveRight{}
		sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
		sCtx.Assert().NotNil(response.HaveRight, "check HaveRight not nil")
		sCtx.Assert().Equal(true, response.HaveRight, "check right was added")
	})
}
