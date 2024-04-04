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

func TestGrayListDelFromList(t *testing.T) {
	nameList := GrayList
	delFromList(t, nameList)
}

func TestBlackListDelFromList(t *testing.T) {
	nameList := BlackList
	delFromList(t, nameList)
}

func TestDelUserFromGrayAndBlackList(t *testing.T) {
	runner.Run(t, "delete user from gray or black list for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for DelFromList method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add user to gray list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "addToList", user.UserAddressBase58Check, GrayList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Add user to black list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "addToList", user.UserAddressBase58Check, BlackList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Check user addet to list by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
			sCtx.Assert().NoError(err)
			t.Log(resp)

			response := &pb.AclResponse{}
			sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
			sCtx.Assert().True(response.Account.GrayListed, "check account is grayListed")
			sCtx.Assert().True(response.Account.BlackListed, "check account is blackListed")
		})

		t.WithNewStep("Delete user from gray list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "delFromList", user.UserAddressBase58Check, GrayList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Delete user from black list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "delFromList", user.UserAddressBase58Check, BlackList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Check user deleted from gray and black lists by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
			sCtx.Assert().NoError(err)
			t.Log(resp)

			response := &pb.AclResponse{}
			sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
			sCtx.Assert().NotNil(response.Address, "check address not nill")
			sCtx.Assert().NotNil(response.Account, "check zccount not nill")
			sCtx.Assert().Equal(user.UserAddressBase58Check, response.Address.Address.AddrString(), "check address")
			sCtx.Assert().False(response.Account.GrayListed, "check account is grayListed")
			sCtx.Assert().False(response.Account.BlackListed, "check account is blackListed")
		})
	})
}

func delFromList(t *testing.T, nameList string) {
	runner.Run(t, "delete user from gray or black list for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for DelFromList method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Add user to "+nameList+" list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "addToList", user.UserAddressBase58Check, nameList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Check user addet to list by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
			sCtx.Assert().NoError(err)
			t.Log(resp)

			response := &pb.AclResponse{}
			sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))

			if nameList == GrayList {
				sCtx.Assert().True(response.Account.GrayListed, "check account is grayListed")
				sCtx.Assert().False(response.Account.BlackListed, "check account is blackListed")
			} else {
				sCtx.Assert().False(response.Account.GrayListed, "check account is grayListed")
				sCtx.Assert().True(response.Account.BlackListed, "check account is blackListed")
			}
		})

		// there is no error if user is deleted from the list, which is not a member
		t.WithNewStep("Delete user from list in which he is not recorded ", func(sCtx provider.StepCtx) {
			var err error

			if nameList == GrayList {
				_, err = hlfProxy.Invoke("acl", "delFromList", user.UserAddressBase58Check, BlackList)
			} else {
				_, err = hlfProxy.Invoke("acl", "delFromList", user.UserAddressBase58Check, GrayList)
			}
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Delete user from "+nameList+" list", func(sCtx provider.StepCtx) {
			_, err := hlfProxy.Invoke("acl", "delFromList", user.UserAddressBase58Check, nameList)
			sCtx.Assert().NoError(err)
		})

		t.WithNewStep("Check user deleted from "+nameList+" list by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
			sCtx.Assert().NoError(err)
			t.Log(resp)

			response := &pb.AclResponse{}
			sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
			sCtx.Assert().NotNil(response.Address, "check address not nill")
			sCtx.Assert().NotNil(response.Account, "check zccount not nill")
			sCtx.Assert().Equal(user.UserAddressBase58Check, response.Address.Address.AddrString(), "check address")

			if nameList == GrayList {
				sCtx.Assert().False(response.Account.GrayListed, "check account is grayListed")
			} else {
				sCtx.Assert().False(response.Account.BlackListed, "check account is blackListed")
			}
		})
	})
}
