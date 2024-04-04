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
	BlackList = "black"
	GrayList  = "gray"
)

func TestGrayListAddToList(t *testing.T) {
	nameList := GrayList
	addToList(t, nameList)
}

func TestBlackListAddToList(t *testing.T) {
	nameList := BlackList
	addToList(t, nameList)
}

func TestAddUserToGrayAndBlackList(t *testing.T) {
	runner.Run(t, "add user to gray and black list for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for AddToList method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add user to gray list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "addToList", user.UserAddressBase58Check, GrayList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Check user added only to gray list by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
			sCtx.Assert().NoError(err)

			response := &pb.AclResponse{}
			sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
			sCtx.Assert().NotNil(response.Address, "check address not nill")
			sCtx.Assert().NotNil(response.Account, "check zccount not nill")
			sCtx.Assert().Equal(user.UserAddressBase58Check, response.Address.Address.AddrString(), "check address")
			sCtx.Assert().True(response.Account.GrayListed, "check account is grayListed")
			sCtx.Assert().False(response.Account.BlackListed, "check account is blackListed")
		})

		t.WithNewStep("Add user to black list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "addToList", user.UserAddressBase58Check, BlackList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Check user added to gray and black list by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
			sCtx.Assert().NoError(err)

			response := &pb.AclResponse{}
			sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
			sCtx.Assert().NotNil(response.Address, "check address not nill")
			sCtx.Assert().NotNil(response.Account, "check zccount not nill")
			sCtx.Assert().Equal(user.UserAddressBase58Check, response.Address.Address.AddrString(), "check address")
			sCtx.Assert().True(response.Account.GrayListed, "check account is grayListed")
			sCtx.Assert().True(response.Account.BlackListed, "check account is blackListed")
		})
	})
}

func addToList(t *testing.T, nameList string) {
	runner.Run(t, "add user to gray or black list for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for AddToList method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add user to "+nameList+" list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "addToList", user.UserAddressBase58Check, nameList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Check user added to list by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
			sCtx.Assert().NoError(err)

			response := &pb.AclResponse{}
			sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
			sCtx.Assert().NotNil(response.Address, "check address not nill")
			sCtx.Assert().NotNil(response.Account, "check zccount not nill")
			sCtx.Assert().Equal(user.UserAddressBase58Check, response.Address.Address.AddrString(), "check address")

			if nameList == GrayList {
				sCtx.Assert().True(response.Account.GrayListed, "check account is grayListed")
				sCtx.Assert().False(response.Account.BlackListed, "check account is blackListed")
			} else {
				sCtx.Assert().False(response.Account.GrayListed, "check account is grayListed")
				sCtx.Assert().True(response.Account.BlackListed, "check account is blackListed")
			}
		})
	})
}
