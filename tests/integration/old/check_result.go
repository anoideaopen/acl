package old

import (
	"fmt"
	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/sha3"
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

func addressFromUser(user *client.UserFoundation) (*pb.Address, error) {
	bytes, err := helpers.DecodeBase58PublicKey(user.PublicKeyBase58)
	if err != nil {
		return nil, fmt.Errorf("failed decoding public key: %w", err)
	}
	hashed := sha3.Sum256(bytes)
	address := hashed[:]

	return &pb.Address{
		UserID:       user.UserID,
		Address:      address,
		IsIndustrial: true,
		IsMultisig:   false,
	}, nil
}

func checkAddress(etalon *pb.SignedAddress) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.Address
		if err := proto.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}

		if aclRes.AddrString() != etalon.Address.AddrString() {
			return "address not equals to etalon"
		}
		if aclRes.UserID != etalon.Address.UserID {
			return "user id not equals to etalon"
		}
		if aclRes.IsIndustrial != etalon.Address.IsIndustrial {
			return "IsIndustrial not equals to etalon"
		}
		if aclRes.IsMultisig != etalon.Address.IsMultisig {
			return "IsMultisig not equals to etalon"
		}
		return ""

	}
}

func checkKeys(etalon *pb.AclResponse) func([]byte) string {
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
		if aclRes.Account.KycHash != etalon.Account.GetKycHash() {
			return "kyc hash not equals to etalon"
		}
		if aclRes.Account.GrayListed != etalon.Account.GetGrayListed() {
			return "graylisted not equals to etalon"
		}
		if aclRes.Account.BlackListed != etalon.Account.GetBlackListed() {
			return "blacklisted not equals to etalon"
		}
		if aclRes.Address.Address.AddrString() != etalon.Address.Address.AddrString() {
			return "address not equals to etalon"
		}
		if aclRes.Address.Address.UserID != etalon.Address.Address.UserID {
			return "user id not equals to etalon"
		}
		if aclRes.Address.Address.IsIndustrial != etalon.Address.Address.IsIndustrial {
			return "IsIndustrial not equals to etalon"
		}
		if aclRes.Address.Address.IsMultisig != etalon.Address.Address.IsMultisig {
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

func checkRights(etalonRightsSet []*pb.Right, aclRightsSet []*pb.Right) string {
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
				rightRes.Address.AddrString() == rightEtalon.Address.AddrString() &&
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

func checkGetAccountAllRights(etalon *pb.AccountRights) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.AccountRights
		if err := protojson.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}
		if aclRes.Address == nil {
			return "address is nil"
		}
		if etalon.Rights != nil && aclRes.Rights == nil {
			return "rights are nil"
		}
		if aclRes.Address.AddrString() != etalon.Address.AddrString() {
			return "address not equals to etalon"
		}
		if aclRes.Address.UserID != etalon.Address.UserID {
			return "user id not equals to etalon"
		}

		return checkRights(etalon.Rights, aclRes.Rights)
	}
}

func checkGetOperationAllRights(etalon *pb.OperationRights) func([]byte) string {
	return func(out []byte) string {
		var aclRes pb.OperationRights
		if err := protojson.Unmarshal(out, &aclRes); err != nil {
			return "cannot unmarshal acl response"
		}
		if aclRes.OperationName != etalon.OperationName {
			return "operation name not equals to etalon"
		}

		return checkRights(etalon.Rights, aclRes.Rights)
	}
}
