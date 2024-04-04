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

const (
	channelName   = "ACL"
	chaincodeName = "acl"
	roleName      = "issuer"
	operationName = "emit"
)

func TestAddRights(t *testing.T) {
	runner.Run(t, "add rights user for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for AddRights method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "addRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountOperationRightCheck(ctx, t, user)
		getAccountAllRightsCheck(ctx, t, user)
		getOperationAllRightsCheck(ctx, t)

		removeRightsAndCheck(ctx, t, user)
	})
}

func TestAddRightsAgain(t *testing.T) {
	runner.Run(t, "add rghts again for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for double AddRights method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "addRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Add rights for added user of chaincode `acl` again", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "addRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)
		})

		getAccountOperationRightCheck(ctx, t, user)
		getAccountAllRightsCheck(ctx, t, user)
		removeRightsAndCheck(ctx, t, user)
	})
}

func removeRightsAndCheck(ctx context.Context, t provider.T, user utils.User) {
	t.WithNewStep("Remove rights for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
		_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "removeRights", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
		sCtx.Assert().NoError(err)
	})

	t.WithNewStep("Checking all rights were removed for added user of chaincode `acl` by getAccountOperationRight", func(sCtx provider.StepCtx) {
		resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
			os.Getenv(utils.HlfProxyAuthToken), "acl", "getAccountOperationRight", nil, channelName, chaincodeName, roleName, operationName, user.UserAddressBase58Check)
		sCtx.Assert().NoError(err)

		response := &pb.HaveRight{}
		sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
		sCtx.Assert().NotNil(response.HaveRight, "check HaveRight not nil")
		sCtx.Assert().Equal(false, response.HaveRight, "check right was added")
	})
}
