package client

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/anoideaopen/acl/tests/common"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

const MultisignKeyDelimeter = "/"

func CheckUserMultisigned(network *nwo.Network, peer *nwo.Peer, user *UserFoundationMultisigned) {
	Eventually(func() string {
		sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
			ChannelID: cmn.ChannelAcl,
			Name:      cmn.ChannelAcl,
			Ctor:      cmn.CtorFromSlice([]string{common.FnCheckKeys, user.PublicKey()}),
		})
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit())
		Expect(sess.ExitCode()).To(Equal(0))
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s, %v", sess.ExitCode(), string(sess.Err.Contents()), err)
		}

		out := sess.Out.Contents()[:len(sess.Out.Contents())-1] // skip line feed
		resp := &pb.AclResponse{}
		err = proto.Unmarshal(out, resp)
		Expect(err).NotTo(HaveOccurred())
		if err != nil {
			return fmt.Sprintf("failed to unmarshal response: %v", err)
		}

		addressBytes := resp.GetAddress().GetAddress().GetAddress()
		addr := base58.CheckEncode(addressBytes[1:], addressBytes[0])
		if addr != user.AddressBase58Check {
			return fmt.Sprintf("Error: expected %s, received %s", user.AddressBase58Check, addr)
		}

		return ""
	}, network.EventuallyTimeout, time.Second).Should(BeEmpty())
}

// AddMultisig adds multisigned user
func AddMultisig(network *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer, n int, user *UserFoundationMultisigned) {
	ctorArgs := []string{common.FnAddMultisig, strconv.Itoa(n), client.NewNonceByTime().Get()}
	publicKeys, sMsgsByte, err := user.Sign(ctorArgs...)
	var sMsgsStr []string
	for _, sMsgByte := range sMsgsByte {
		sMsgsStr = append(sMsgsStr, hex.EncodeToString(sMsgByte))
	}
	ctorArgs = append(append(ctorArgs, publicKeys...), sMsgsStr...)
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

	CheckUserMultisigned(network, peer, user)
}

// ChangeMultisigPublicKey changes public key for multisigned user by validators
func ChangeMultisigPublicKey(
	network *nwo.Network,
	peer *nwo.Peer,
	orderer *nwo.Orderer,
	multisignedUser *UserFoundationMultisigned,
	oldPubKeyBase58 string,
	newPubKeyBase58 string,
	reason string,
	reasonID string,
	validators ...*client.UserFoundation,
) {
	nonce := client.NewNonceByTime().Get()
	// ToDo - Why are we signing arguments that differs we are sending?
	ctorArgsToSign := []string{common.FnChangeMultisigPublicKey, multisignedUser.AddressBase58Check, oldPubKeyBase58, multisignedUser.PublicKey(), reason, reasonID, nonce}
	validatorMultisignedUser := &UserFoundationMultisigned{
		UserID: "multisigned validators",
		Users:  validators,
	}

	pKeys, sMsgsByte, err := validatorMultisignedUser.Sign(ctorArgsToSign...)
	Expect(err).NotTo(HaveOccurred())

	var sMsgsStr []string
	ctorArgs := []string{common.FnChangeMultisigPublicKey, multisignedUser.AddressBase58Check, oldPubKeyBase58, newPubKeyBase58, reason, reasonID, nonce}
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

	CheckUserMultisigned(network, peer, multisignedUser)
}
