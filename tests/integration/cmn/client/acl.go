package client

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/anoideaopen/acl/cc"
	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"google.golang.org/protobuf/proto"
)

// AddToBlackList adds user to a black list
func AddToBlackList(network *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer, user *client.UserFoundation) {
	addToList(network, peer, orderer, cc.BlackList, user)
}

// AddToGrayList adds user to a gray list
func AddToGrayList(network *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer, user *client.UserFoundation) {
	addToList(network, peer, orderer, cc.GrayList, user)
}

func addToList(
	network *nwo.Network,
	peer *nwo.Peer,
	orderer *nwo.Orderer,
	listType cc.ListType,
	user *client.UserFoundation,
) {
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelAcl,
		Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
		Name:      cmn.ChannelAcl,
		Ctor: cmn.CtorFromSlice([]string{
			common.FnAddToList,
			user.AddressBase58Check,
			listType.String(),
		}),
		PeerAddresses: []string{
			network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
			network.PeerAddress(network.Peer("Org2", "peer0"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	CheckUserInList(network, peer, listType, user)
}

// DelFromBlackList adds user to a black list
func DelFromBlackList(network *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer, user *client.UserFoundation) {
	delFromList(network, peer, orderer, cc.BlackList, user)
}

// DelFromGrayList adds user to a gray list
func DelFromGrayList(network *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer, user *client.UserFoundation) {
	delFromList(network, peer, orderer, cc.GrayList, user)
}

func delFromList(
	network *nwo.Network,
	peer *nwo.Peer,
	orderer *nwo.Orderer,
	listType cc.ListType,
	user *client.UserFoundation,
) {
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelAcl,
		Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
		Name:      cmn.ChannelAcl,
		Ctor: cmn.CtorFromSlice([]string{
			common.FnDelFromList,
			user.AddressBase58Check,
			listType.String(),
		}),
		PeerAddresses: []string{
			network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
			network.PeerAddress(network.Peer("Org2", "peer0"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	CheckUserNotInList(network, peer, listType, user)
}

// CheckUserInList - checks if user in gray or black list
func CheckUserInList(
	network *nwo.Network,
	peer *nwo.Peer,
	listType cc.ListType,
	user *client.UserFoundation,
) {
	Eventually(func() string {
		sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
			ChannelID: cmn.ChannelAcl,
			Name:      cmn.ChannelAcl,
			Ctor:      cmn.CtorFromSlice([]string{common.FnCheckKeys, user.PublicKeyBase58}),
		})
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit())
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s, %v", sess.ExitCode(), string(sess.Err.Contents()), err)
		}

		out := sess.Out.Contents()[:len(sess.Out.Contents())-1] // skip line feed
		resp := &pb.AclResponse{}
		err = proto.Unmarshal(out, resp)
		if err != nil {
			return fmt.Sprintf("failed to unmarshal response: %v", err)
		}

		addr := base58.CheckEncode(resp.GetAddress().GetAddress().GetAddress()[1:], resp.GetAddress().GetAddress().GetAddress()[0])
		if addr != user.AddressBase58Check {
			return fmt.Sprintf("Error: expected %s, received %s", user.AddressBase58Check, addr)
		}

		account := resp.GetAccount()
		if !((account.GetBlackListed() && listType == cc.BlackList) || (account.GetGrayListed() && listType == cc.GrayList)) {
			return fmt.Sprintf("Error: expected %s to be added to %s", user.AddressBase58Check, listType.String())
		}

		return ""
	}, network.EventuallyTimeout, time.Second).Should(BeEmpty())
}

// CheckUserNotInList - checks if user in gray or black list
func CheckUserNotInList(
	network *nwo.Network,
	peer *nwo.Peer,
	listType cc.ListType,
	user *client.UserFoundation,
) {
	Eventually(func() string {
		sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
			ChannelID: cmn.ChannelAcl,
			Name:      cmn.ChannelAcl,
			Ctor:      cmn.CtorFromSlice([]string{common.FnCheckKeys, user.PublicKeyBase58}),
		})
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit())
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s, %v", sess.ExitCode(), string(sess.Err.Contents()), err)
		}

		out := sess.Out.Contents()[:len(sess.Out.Contents())-1] // skip line feed
		resp := &pb.AclResponse{}
		err = proto.Unmarshal(out, resp)
		if err != nil {
			return fmt.Sprintf("failed to unmarshal response: %v", err)
		}

		addr := base58.CheckEncode(resp.GetAddress().GetAddress().GetAddress()[1:], resp.GetAddress().GetAddress().GetAddress()[0])
		if addr != user.AddressBase58Check {
			return fmt.Sprintf("Error: expected %s, received %s", user.AddressBase58Check, addr)
		}

		account := resp.GetAccount()
		if !((!account.GetBlackListed() && listType == cc.BlackList) || (!account.GetGrayListed() && listType == cc.GrayList)) {
			return fmt.Sprintf("Error: expected %s to be deleted from %s", user.AddressBase58Check, listType.String())
		}

		return ""
	}, network.EventuallyTimeout, time.Second).Should(BeEmpty())
}

func ChangePublicKey(
	network *nwo.Network,
	peer *nwo.Peer,
	orderer *nwo.Orderer,
	user *client.UserFoundation,
	newPubKeyBase58 string,
	reason string,
	reasonID string,
	validators ...*client.UserFoundation,
) {
	ctorArgs := []string{common.FnChangePublicKey, user.AddressBase58Check, reason, reasonID, newPubKeyBase58, client.NewNonceByTime().Get()}
	validatorMultisignedUser := &client.UserFoundationMultisigned{
		UserID: "multisigned validators",
		Users:  validators,
	}

	pKeys, sMsgsByte, err := validatorMultisignedUser.Sign(ctorArgs...)
	Expect(err).NotTo(HaveOccurred())

	sMsgsStr := []string{}
	for _, sMsgByte := range sMsgsByte {
		sMsgsStr = append(sMsgsStr, hex.EncodeToString(sMsgByte))
	}

	ctorArgs = append(append(ctorArgs, pKeys...), sMsgsStr...)
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelAcl,
		Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
		Name:      cmn.ChannelAcl,
		Ctor:      cmn.CtorFromSlice(ctorArgs),
		PeerAddresses: []string{
			network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
			network.PeerAddress(network.Peer("Org2", "peer0"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	CheckUserChangedKey(network, peer, newPubKeyBase58, user.AddressBase58Check)
}

func ChangePublicKeyBase58signed(
	network *nwo.Network,
	peer *nwo.Peer,
	orderer *nwo.Orderer,
	user *client.UserFoundation,
	requestID string,
	chaincodeName string,
	channelID string,
	newPubKeyBase58 string,
	reason string,
	reasonID string,
	validators ...*client.UserFoundation,
) {
	ctorArgs := []string{common.FnChangePublicKeyWithBase58Signature, requestID, chaincodeName, channelID, user.AddressBase58Check, reason, reasonID, newPubKeyBase58, client.NewNonceByTime().Get()}
	validatorMultisignedUser := &client.UserFoundationMultisigned{
		UserID: "multisigned validators",
		Users:  validators,
	}

	pKeys, sMsgsByte, err := validatorMultisignedUser.Sign(ctorArgs...)
	Expect(err).NotTo(HaveOccurred())

	sMsgsStr := []string{}
	for _, sMsgByte := range sMsgsByte {
		sMsgsStr = append(sMsgsStr, base58.Encode(sMsgByte))
	}

	ctorArgs = append(append(ctorArgs, pKeys...), sMsgsStr...)
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelAcl,
		Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
		Name:      cmn.ChannelAcl,
		Ctor:      cmn.CtorFromSlice(ctorArgs),
		PeerAddresses: []string{
			network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
			network.PeerAddress(network.Peer("Org2", "peer0"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	CheckUserChangedKey(network, peer, newPubKeyBase58, user.AddressBase58Check)
}

func CheckUserChangedKey(network *nwo.Network, peer *nwo.Peer, newPublicKeyBase58Check, oldAddressBase58Check string) {
	Eventually(func() string {
		sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
			ChannelID: cmn.ChannelAcl,
			Name:      cmn.ChannelAcl,
			Ctor:      cmn.CtorFromSlice([]string{"checkKeys", newPublicKeyBase58Check}),
		})
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit())
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s, %v", sess.ExitCode(), string(sess.Err.Contents()), err)
		}

		out := sess.Out.Contents()[:len(sess.Out.Contents())-1] // skip line feed
		resp := &pb.AclResponse{}
		err = proto.Unmarshal(out, resp)
		if err != nil {
			return fmt.Sprintf("failed to unmarshal response: %v", err)
		}

		addr := base58.CheckEncode(resp.GetAddress().GetAddress().GetAddress()[1:], resp.GetAddress().GetAddress().GetAddress()[0])
		if addr != oldAddressBase58Check {
			return fmt.Sprintf("Error: expected %s, received %s", oldAddressBase58Check, addr)
		}

		return ""
	}, network.EventuallyTimeout, time.Second).Should(BeEmpty())
}

// CheckAccountInfo checks account info
func CheckAccountInfo(
	network *nwo.Network,
	peer *nwo.Peer,
	user *client.UserFoundation,
	kycHash string,
	isGrayListed,
	isBlackListed bool,
) {
	Eventually(func() string {
		sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
			ChannelID: cmn.ChannelAcl,
			Name:      cmn.ChannelAcl,
			Ctor:      cmn.CtorFromSlice([]string{common.FnGetAccInfoFn, user.AddressBase58Check}),
		})
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit())
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s, %v", sess.ExitCode(), string(sess.Err.Contents()), err)
		}

		out := sess.Out.Contents()[:len(sess.Out.Contents())-1] // skip line feed
		resp := &pb.AccountInfo{}
		err = json.Unmarshal(out, resp)
		if err != nil {
			return fmt.Sprintf("failed to unmarshal response: %v", err)
		}

		if resp.GetKycHash() != kycHash {
			return fmt.Sprintf("kyc check error: expected %s, received %s", kycHash, resp.GetKycHash())
		}

		if resp.GetGrayListed() != isGrayListed {
			return fmt.Sprintf("gray list check error error: expected %t, received %t", isGrayListed, resp.GetGrayListed())
		}

		if resp.GetBlackListed() != isBlackListed {
			return fmt.Sprintf("black list check error: expected %t, received %t", isBlackListed, resp.GetBlackListed())
		}

		return ""
	}, network.EventuallyTimeout, time.Second).Should(BeEmpty())
}

// SetAccountInfo sets account info
func SetAccountInfo(
	network *nwo.Network,
	peer *nwo.Peer,
	orderer *nwo.Orderer,
	user *client.UserFoundation,
	kycHash string,
	isGrayListed,
	isBlackListed bool,
) {
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelAcl,
		Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
		Name:      cmn.ChannelAcl,
		Ctor: cmn.CtorFromSlice([]string{
			"setAccountInfo",
			user.AddressBase58Check,
			kycHash,
			strconv.FormatBool(isGrayListed),
			strconv.FormatBool(isBlackListed),
		}),
		PeerAddresses: []string{
			network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
			network.PeerAddress(network.Peer("Org2", "peer0"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	CheckAccountInfo(network, peer, user, kycHash, isGrayListed, isBlackListed)
}

// SetKYC sets kyc hash
func SetKYC(
	network *nwo.Network,
	peer *nwo.Peer,
	orderer *nwo.Orderer,
	user *client.UserFoundation,
	kycHash string,
	validators ...*client.UserFoundation,
) {
	ctorArgs := []string{common.FnSetKYC, user.AddressBase58Check, kycHash, client.NewNonceByTime().Get()}
	validatorMultisignedUser := &client.UserFoundationMultisigned{
		UserID: "multisigned validators",
		Users:  validators,
	}

	pKeys, sMsgsByte, err := validatorMultisignedUser.Sign(ctorArgs...)
	Expect(err).NotTo(HaveOccurred())

	sMsgsStr := []string{}
	for _, sMsgByte := range sMsgsByte {
		sMsgsStr = append(sMsgsStr, hex.EncodeToString(sMsgByte))
	}

	ctorArgs = append(append(ctorArgs, pKeys...), sMsgsStr...)
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelAcl,
		Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
		Name:      cmn.ChannelAcl,
		Ctor:      cmn.CtorFromSlice(ctorArgs),
		PeerAddresses: []string{
			network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
			network.PeerAddress(network.Peer("Org2", "peer0"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	CheckAccountInfo(network, peer, user, kycHash, false, false)
}
