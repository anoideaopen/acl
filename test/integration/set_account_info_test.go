package integration

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"github.com/stretchr/testify/assert"
	utils "gitlab.n-t.io/core/library/go/atomyze-util"
	pb "gitlab.n-t.io/core/library/go/foundation/v3/proto"
)

const newKycHash = "kycHash2"

type serieSetAccountInfo struct {
	isGraylisted  string
	isBlacklisted string
}

func TestSetAccountInfoFalseLists(t *testing.T) {
	s := &serieSetAccountInfo{
		isGraylisted:  "false",
		isBlacklisted: "false",
	}

	setAccountInfo(t, s)
}

func TestSetAccountInfoTrueGrayListFalseBlackLists(t *testing.T) {
	s := &serieSetAccountInfo{
		isGraylisted:  "true",
		isBlacklisted: "false",
	}

	setAccountInfo(t, s)
}

func TestSetAccountInfoFalseGrayListTrueBlackLists(t *testing.T) {
	s := &serieSetAccountInfo{
		isGraylisted:  "false",
		isBlacklisted: "true",
	}

	setAccountInfo(t, s)
}

func TestSetAccountInfoTrueLists(t *testing.T) {
	s := &serieSetAccountInfo{
		isGraylisted:  "true",
		isBlacklisted: "true",
	}

	setAccountInfo(t, s)
}

func setAccountInfo(t *testing.T, ser *serieSetAccountInfo) {
	runner.Run(t, "set account info for acl chaincode", func(t provider.T) {
		ctx := context.Background()
		t.Severity(allure.BLOCKER)
		t.Description("Tests for SetAccountInfo method for ACL ")
		t.Tags("integration", "acl", "positive")

		hlfProxy := utils.NewHlfProxyService(os.Getenv(utils.HlfProxyURL), os.Getenv(utils.HlfProxyAuthToken))

		user := utils.AddUser(t, *hlfProxy)

		t.WithNewStep("Set account info for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			_, err := utils.Invoke(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "setAccountInfo", nil, user.UserAddressBase58Check, newKycHash, ser.isGraylisted, ser.isBlacklisted)
			sCtx.Assert().NoError(err)
		})

		isGraylistedBool, err := strconv.ParseBool(ser.isGraylisted)
		assert.NoError(t, err)
		isBlacklistedBool, err := strconv.ParseBool(ser.isBlacklisted)
		assert.NoError(t, err)

		t.WithNewStep("Get account info for added user of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "getAccountInfo", nil, user.UserAddressBase58Check)
			sCtx.Assert().NoError(err)

			addrFromLedger := &pb.AccountInfo{}
			sCtx.Assert().NoError(json.Unmarshal(resp.Payload, addrFromLedger))
			sCtx.Assert().Equal(newKycHash, addrFromLedger.KycHash, "check new kycHash")
			sCtx.Assert().Equal(isGraylistedBool, addrFromLedger.GrayListed, "check graylisted state")
			sCtx.Assert().Equal(isBlacklistedBool, addrFromLedger.BlackListed, "check blacklisted state")
		})

		t.WithNewStep("Check user addet to list by querying method `checkKeys` of chaincode `acl`", func(sCtx provider.StepCtx) {
			resp, err := utils.Query(ctx, os.Getenv(utils.HlfProxyURL),
				os.Getenv(utils.HlfProxyAuthToken), "acl", "checkKeys", nil, user.UserPublicKeyBase58)
			sCtx.Assert().NoError(err)

			response := &pb.AclResponse{}
			sCtx.Assert().NoError(proto.Unmarshal(resp.Payload, response))
			sCtx.Assert().NotNil(response.Address, "ckeck address not nill")
			sCtx.Assert().NotNil(response.Account, "ckeck account not nill")
			sCtx.Assert().Equal(user.UserAddressBase58Check, response.Address.Address.AddrString(), "ckeck address")
			sCtx.Assert().Equal(newKycHash, response.Account.KycHash, "check new kycHash")
			sCtx.Assert().Equal(isGraylistedBool, response.Account.GrayListed, "check graylisted state")
			sCtx.Assert().Equal(isBlacklistedBool, response.Account.BlackListed, "check blacklisted state")
		})
	})
}
