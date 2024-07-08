package old

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/anoideaopen/acl/cc"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	testAccountNotListed = &pb.AccountInfo{
		KycHash:     "test",
		GrayListed:  false,
		BlackListed: false,
	}

	testAccountGraylisted = &pb.AccountInfo{
		KycHash:     "test",
		GrayListed:  true,
		BlackListed: false,
	}

	testAccountBlacklisted = &pb.AccountInfo{
		KycHash:     "test",
		GrayListed:  false,
		BlackListed: true,
	}

	testAccountBothLists = &pb.AccountInfo{
		KycHash:     "test",
		GrayListed:  true,
		BlackListed: true,
	}

	testHaveRight   = &pb.HaveRight{HaveRight: true}
	testHaveNoRight = &pb.HaveRight{HaveRight: false}
)

func checkAddress(etalon *client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.Address
		if err := proto.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}

		if aclRes.AddrString() != etalon.AddressBase58Check {
			return "address not equals to etalon"
		}
		if aclRes.UserID != etalon.UserID {
			return "user id not equals to etalon"
		}
		if aclRes.IsIndustrial != true {
			return "IsIndustrial not equals to etalon"
		}
		if aclRes.IsMultisig != false {
			return "IsMultisig not equals to etalon"
		}
		return ""

	}
}

func checkAddressGraylisted(message string) func([]byte) string {
	return func(out []byte) string {
		if strings.Contains(string(out), message) {
			return fmt.Sprintf("out string %s not contains message: %s", string(out), message)
		}
		return ""
	}
}

func checkKeys(account *pb.AccountInfo, user *client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.AclResponse
		if err := proto.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}

		if aclRes.Address == nil {
			return "address is nil"
		}
		if aclRes.Account == nil {
			return "account is nil"
		}
		if aclRes.Account.KycHash != account.GetKycHash() {
			return "kyc hash not equals to etalon"
		}
		if aclRes.Account.GrayListed != account.GetGrayListed() {
			return "graylisted not equals to etalon"
		}
		if aclRes.Account.BlackListed != account.GetBlackListed() {
			return "blacklisted not equals to etalon"
		}
		if aclRes.Address.Address.AddrString() != user.AddressBase58Check {
			return "address not equals to etalon"
		}
		if aclRes.Address.Address.UserID != user.UserID {
			return "user id not equals to etalon"
		}
		if aclRes.Address.Address.IsIndustrial != true {
			return "IsIndustrial not equals to etalon"
		}
		if aclRes.Address.Address.IsMultisig != false {
			return "IsMultisig not equals to etalon"
		}
		return ""
	}
}

func checkGetAccountOperationRight(etalon *pb.HaveRight) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.HaveRight
		if err := proto.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}

		if aclRes.HaveRight != etalon.HaveRight {
			return "right not equals to etalon"
		}

		return ""
	}
}

func checkRights(etalonRightsSet []*pb.Right, aclRightsSet []*pb.Right, user *client.UserFoundation) string {
	etalonRights := make([]*pb.Right, len(etalonRightsSet))
	for i, right := range etalonRightsSet {
		etalonRights[i] = right
	}
	for _, rightRes := range aclRightsSet {
		for i, rightEtalon := range etalonRights {
			if rightRes.ChannelName == rightEtalon.ChannelName &&
				rightRes.ChaincodeName == rightEtalon.ChaincodeName &&
				rightRes.RoleName == rightEtalon.RoleName &&
				rightRes.OperationName == rightEtalon.OperationName &&
				rightRes.Address.AddrString() == user.AddressBase58Check &&
				rightRes.HaveRight.HaveRight == rightEtalon.HaveRight.HaveRight {
				etalonRights = append(etalonRights[:i], etalonRights[i+1:]...)
				break
			}
		}
	}

	if len(etalonRights) != 0 {
		return fmt.Sprintf("some etalon rights not found: %v", etalonRights)
	}

	return ""
}

func checkGetAccountAllRights(accountRights []*pb.Right, user *client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.AccountRights
		if err := protojson.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}
		if aclRes.Address == nil {
			return "address is nil"
		}
		if len(accountRights) > 0 && aclRes.Rights == nil {
			return "rights are nil"
		}
		if aclRes.Address.AddrString() != user.AddressBase58Check {
			return "address not equals to etalon"
		}
		if aclRes.Address.UserID != user.UserID {
			return "user id not equals to etalon"
		}

		return checkRights(accountRights, aclRes.Rights, user)
	}
}

func checkGetOperationAllRights(etalon *pb.OperationRights, user *client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.OperationRights
		if err := protojson.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}
		if aclRes.OperationName != etalon.OperationName {
			return "operation name not equals to etalon"
		}

		return checkRights(etalon.Rights, aclRes.Rights, user)
	}
}

func checkAccountInfo(etalon *pb.AccountInfo) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.AccountInfo
		if err := json.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}

		if aclRes.GetKycHash() != etalon.GetKycHash() {
			return fmt.Sprintf("kycHash not equals to etalon - expected %s, got %s", etalon.GetKycHash(), aclRes.GetKycHash())
		}

		if aclRes.GetGrayListed() != etalon.GetGrayListed() {
			return "gray listed not equals to etalon"
		}

		if aclRes.GetBlackListed() != etalon.GetBlackListed() {
			return "black listed not equals to etalon"
		}

		return ""
	}
}

func checkAddresses(users ...*client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		var aclRes cc.AddrsWithPagination
		if err := json.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}

		for _, user := range users {
			if !slices.Contains(aclRes.Addrs, user.AddressBase58Check) {
				return "user not found"
			}
		}

		return ""
	}
}
