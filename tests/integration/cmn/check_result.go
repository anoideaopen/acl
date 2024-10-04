package cmn

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/anoideaopen/acl/cc"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	ErrUserIDNotEtalon         = "user id not equals to etalon"
	ErrAddressNotEtalon        = "address not equals to etalon"
	ErrCannotUnmarshalResponse = "cannot unmarshal acl response"
)

var (
	TestAccountNotListed = &pb.AccountInfo{
		KycHash:     "test",
		GrayListed:  false,
		BlackListed: false,
	}

	TestAccountGraylisted = &pb.AccountInfo{
		KycHash:     "test",
		GrayListed:  true,
		BlackListed: false,
	}

	TestAccountBlacklisted = &pb.AccountInfo{
		KycHash:     "test",
		GrayListed:  false,
		BlackListed: true,
	}

	TestAccountBothLists = &pb.AccountInfo{
		KycHash:     "test",
		GrayListed:  true,
		BlackListed: true,
	}

	TestHaveRight   = &pb.HaveRight{HaveRight: true}
	TestHaveNoRight = &pb.HaveRight{HaveRight: false}
)

func CheckAddress(etalon *client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		out = out[:len(out)-1] // skip line feed
		var aclRes pb.Address
		if err := proto.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
		}

		if aclRes.AddrString() != etalon.AddressBase58Check {
			return ErrAddressNotEtalon
		}
		if aclRes.GetUserID() != etalon.UserID {
			return ErrUserIDNotEtalon
		}
		if !aclRes.GetIsIndustrial() {
			return "IsIndustrial not equals to etalon"
		}
		if aclRes.GetIsMultisig() {
			return "IsMultisig not equals to etalon"
		}

		return ""
	}
}

func CheckAddressGraylisted(message string) func([]byte) string {
	return func(out []byte) string {
		if strings.Contains(string(out), message) {
			return fmt.Sprintf("out string %s not contains message: %s", string(out), message)
		}
		return ""
	}
}

func CheckKeys(account *pb.AccountInfo, user *client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		out = out[:len(out)-1] // skip line feed
		var aclRes pb.AclResponse
		if err := proto.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
		}

		if aclRes.GetAddress() == nil {
			return "address is nil"
		}

		aclResAddress := aclRes.GetAddress().GetAddress()
		aclResAccount := aclRes.GetAccount()
		if aclRes.GetAccount() == nil {
			return "account is nil"
		}
		if aclResAccount.GetKycHash() != account.GetKycHash() {
			return "kyc hash not equals to etalon"
		}
		if aclResAccount.GetGrayListed() != account.GetGrayListed() {
			return "graylisted not equals to etalon"
		}
		if aclResAccount.GetBlackListed() != account.GetBlackListed() {
			return "blacklisted not equals to etalon"
		}
		if aclResAddress.AddrString() != user.AddressBase58Check {
			return ErrAddressNotEtalon
		}
		if aclResAddress.GetUserID() != user.UserID {
			return ErrUserIDNotEtalon
		}
		if !aclResAddress.GetIsIndustrial() {
			return "IsIndustrial not equals to etalon"
		}
		if aclResAddress.GetIsMultisig() {
			return "IsMultisig not equals to etalon"
		}
		return ""
	}
}

func CheckGetAccountOperationRight(etalon *pb.HaveRight) func([]byte) string {
	return func(out []byte) string {
		out = out[:len(out)-1] // skip line feed
		var aclRes pb.HaveRight
		if err := proto.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
		}

		if aclRes.GetHaveRight() != etalon.GetHaveRight() {
			return "right not equals to etalon"
		}

		return ""
	}
}

func CheckRights(etalonRightsSet []*pb.Right, aclRightsSet []*pb.Right, user *client.UserFoundation) string {
	etalonRights := make([]*pb.Right, len(etalonRightsSet))
	copy(etalonRights, etalonRightsSet)
	for _, rightRes := range aclRightsSet {
		for i, rightEtalon := range etalonRights {
			if rightRes.GetChannelName() == rightEtalon.GetChannelName() &&
				rightRes.GetChaincodeName() == rightEtalon.GetChaincodeName() &&
				rightRes.GetRoleName() == rightEtalon.GetRoleName() &&
				rightRes.GetOperationName() == rightEtalon.GetOperationName() &&
				rightRes.GetAddress().AddrString() == user.AddressBase58Check &&
				rightRes.GetHaveRight().GetHaveRight() == rightEtalon.GetHaveRight().GetHaveRight() {
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

func CheckGetAccountAllRights(accountRights []*pb.Right, user *client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.AccountRights
		if err := protojson.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
		}
		aclResAddress := aclRes.GetAddress()
		if aclResAddress == nil {
			return "address is nil"
		}
		aclResRights := aclRes.GetRights()
		if len(accountRights) > 0 && aclResRights == nil {
			return "rights are nil"
		}
		if aclResAddress.AddrString() != user.AddressBase58Check {
			return ErrAddressNotEtalon
		}
		if aclResAddress.GetUserID() != user.UserID {
			return ErrUserIDNotEtalon
		}

		return CheckRights(accountRights, aclResRights, user)
	}
}

func CheckGetOperationAllRights(etalon *pb.OperationRights, user *client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.OperationRights
		if err := protojson.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
		}
		if aclRes.GetOperationName() != etalon.GetOperationName() {
			return "operation name not equals to etalon"
		}

		return CheckRights(etalon.GetRights(), aclRes.GetRights(), user)
	}
}

func CheckAccountInfo(etalon *pb.AccountInfo) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.AccountInfo
		if err := json.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
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

func CheckAddresses(users ...*client.UserFoundation) func([]byte) string {
	return func(out []byte) string {
		var aclRes cc.AddrsWithPagination
		if err := json.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
		}

		for _, user := range users {
			if !slices.Contains(aclRes.Addrs, user.AddressBase58Check) {
				return "user not found"
			}
		}

		return ""
	}
}

func CheckGetAddressesListForNominee(addresses []string) func([]byte) string {
	return func(out []byte) string {
		out = out[:len(out)-1] // skip line feed
		var aclRes pb.Accounts
		if err := protojson.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
		}

		if len(aclRes.GetAddresses()) != len(addresses) {
			return "addresses count not equals to etalon"
		}

		qty := 0
		for _, etalonAddress := range addresses {
			for _, address := range aclRes.GetAddresses() {
				if address.AddrString() == etalonAddress {
					qty++
					break
				}
			}
		}

		if qty != len(addresses) {
			return "addresses not equals to etalon"
		}

		return ""
	}
}

func CheckAddressRightForNominee(haveRight bool) func(b []byte) string {
	return func(out []byte) string {
		out = out[:len(out)-1] // skip line feed
		var aclRes pb.HaveRight
		if err := protojson.Unmarshal(out, &aclRes); err != nil {
			return ErrCannotUnmarshalResponse
		}

		if aclRes.HaveRight != haveRight {
			return "haveRight not equals to etalon"
		}

		return ""
	}
}
