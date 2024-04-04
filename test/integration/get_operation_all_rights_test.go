package integration

import (
	"context"
	"os"
	"testing"

	//nolint:staticcheck
	"github.com/golang/protobuf/proto"
	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	utils "gitlab.n-t.io/core/library/go/atomyze-util"
	pb "gitlab.n-t.io/core/library/go/foundation/v3/proto"
)

func TestGetOperationAllRights(t *testing.T) {
	runner.Run(t, "Get operation all rights user for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for GetOperationAllRights method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "addRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getOperationAllRightsCheck(ctx, t)

		t.WithNewStep("Remove rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "removeRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getOperationAllRightsCheckRemove(ctx, t)
	})
}

func getOperationAllRightsCheck(ctx context.Context, t provider.T) {
	t.WithNewStep("Checking user rights for added user of chaincode `acl` by getOperationAllRights", func(sCtx provider.StepCtx) {
		resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "getOperationAllRights", nil, channelName, chaincodeName, roleName, operationName)
		sCtx.Assert().NoError(err)

		response := &pb.OperationRights{}
		sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
		sCtx.Assert().NotNil(response.OperationName, "check operationName not nil")
		sCtx.Assert().NotNil(response.Rights, "check rights not nil")
		sCtx.Assert().Equal(operationName, response.OperationName, "check operationName")
	})
}

func getOperationAllRightsCheckRemove(ctx context.Context, t provider.T) {
	t.WithNewStep("Checking user rights after remove for added user of chaincode `acl` by getOperationAllRights", func(sCtx provider.StepCtx) {
		resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "getOperationAllRights", nil, channelName, chaincodeName, roleName, operationName)
		sCtx.Assert().NoError(err)

		response := &pb.OperationRights{}
		sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
		sCtx.Assert().NotNil(response.OperationName, "check operationName not nil")
		sCtx.Assert().Nil(response.Rights, "check rights equal nil")
		sCtx.Assert().Equal(operationName, response.OperationName, "check operationName")
		sCtx.Assert().Len(response.Rights, 0, "check rights len")
	})
}
