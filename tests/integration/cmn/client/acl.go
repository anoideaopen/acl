package client

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anoideaopen/foundation/mocks"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	fclient "github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	FnAddAdditionalKey    = "addAdditionalKey"
	FnRemoveAdditionalKey = "removeAdditionalKey"
)

type ACLTestSuite struct {
	*fclient.FoundationTestSuite
}

func NewTestSuite(components *nwo.Components, opts ...fclient.UserOption) *ACLTestSuite {
	return &ACLTestSuite{FoundationTestSuite: fclient.NewTestSuite(components, opts...)}
}

func (ts *ACLTestSuite) CheckAddressForNominee(
	channelName string,
	chaincodeName string,
	nominee *mocks.UserFoundation,
	principal *mocks.UserFoundation,
	haveRight bool,
) {
	Eventually(func() string {
		sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeQuery{
			ChannelID: cmn.ChannelACL,
			Name:      cmn.ChannelACL,
			Ctor:      cmn.CtorFromSlice([]string{"getAddressRightForNominee", channelName, chaincodeName, nominee.AddressBase58Check, principal.AddressBase58Check}),
		})
		Eventually(sess, ts.Network.EventuallyTimeout).Should(gexec.Exit())
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s, %v", sess.ExitCode(), string(sess.Err.Contents()), err)
		}

		out := sess.Out.Contents()[:len(sess.Out.Contents())-1] // skip line feed
		resp := &pb.HaveRight{}
		err = protojson.Unmarshal(out, resp)
		if err != nil {
			return fmt.Sprintf("failed to unmarshal response: %v", err)
		}

		Expect(resp.GetHaveRight()).To(BeEquivalentTo(haveRight))

		return ""
	}, ts.Network.EventuallyTimeout, time.Second).Should(BeEmpty())
}

func (ts *ACLTestSuite) AddAddressForNominee(
	channelName string,
	chaincodeName string,
	nominee *mocks.UserFoundation,
	principal *mocks.UserFoundation,
) {
	sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelACL,
		Orderer:   ts.Network.OrdererAddress(ts.Orderer, nwo.ListenPort),
		Name:      cmn.ChannelACL,
		Ctor: cmn.CtorFromSlice([]string{
			"addAddressForNominee",
			channelName,
			chaincodeName,
			nominee.AddressBase58Check,
			principal.AddressBase58Check,
		}),
		PeerAddresses: []string{
			ts.Network.PeerAddress(ts.Network.Peer(ts.Org1Name, ts.Peer.Name), nwo.ListenPort),
			ts.Network.PeerAddress(ts.Network.Peer(ts.Org2Name, ts.Peer.Name), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, ts.Network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	ts.CheckAddressForNominee(channelName, chaincodeName, nominee, principal, true)
}

func (ts *ACLTestSuite) RemoveAddressFromNominee(
	channelName string,
	chaincodeName string,
	nominee *mocks.UserFoundation,
	principal *mocks.UserFoundation,
) {
	sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelACL,
		Orderer:   ts.Network.OrdererAddress(ts.Orderer, nwo.ListenPort),
		Name:      cmn.ChannelACL,
		Ctor: cmn.CtorFromSlice([]string{
			"removeAddressFromNominee",
			channelName,
			chaincodeName,
			nominee.AddressBase58Check,
			principal.AddressBase58Check,
		}),
		PeerAddresses: []string{
			ts.Network.PeerAddress(ts.Network.Peer(ts.Org1Name, ts.Peer.Name), nwo.ListenPort),
			ts.Network.PeerAddress(ts.Network.Peer(ts.Org2Name, ts.Peer.Name), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, ts.Network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	ts.CheckAddressForNominee(channelName, chaincodeName, nominee, principal, false)
}

func (ts *ACLTestSuite) AddAdditionalKey(
	user *mocks.UserFoundation,
	base58additionalKey string,
	labels []string,
	validators ...*mocks.UserFoundation,
) {
	nc := fclient.NewNonceByTime().Get()

	rawLabels, err := json.Marshal(labels)
	Expect(err).NotTo(HaveOccurred())

	ctorArgs := []string{FnAddAdditionalKey, user.AddressBase58Check, base58additionalKey, string(rawLabels), nc}
	validatorMultisignedUser := &mocks.UserFoundationMultisigned{
		UserID: "multisigned validators",
		Users:  validators,
	}

	pKeys, sMsgsByte, err := validatorMultisignedUser.Sign(ctorArgs...)
	Expect(err).NotTo(HaveOccurred())

	sMsgsStr := make([]string, 0, len(sMsgsByte))
	for _, sMsgByte := range sMsgsByte {
		sMsgsStr = append(sMsgsStr, hex.EncodeToString(sMsgByte))
	}

	ctorArgs = append(append(ctorArgs, pKeys...), sMsgsStr...)

	sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelACL,
		Orderer:   ts.Network.OrdererAddress(ts.Orderer, nwo.ListenPort),
		Name:      cmn.ChannelACL,
		Ctor:      cmn.CtorFromSlice(ctorArgs),
		PeerAddresses: []string{
			ts.Network.PeerAddress(ts.Network.Peer(ts.Org1Name, ts.Peer.Name), nwo.ListenPort),
			ts.Network.PeerAddress(ts.Network.Peer(ts.Org2Name, ts.Peer.Name), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, ts.Network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	ts.CheckAdditionalKey(user, base58additionalKey, true)
}

func (ts *ACLTestSuite) RemoveAdditionalKey(
	user *mocks.UserFoundation,
	base58additionalKey string,
	validators ...*mocks.UserFoundation,
) {
	nc := fclient.NewNonceByTime().Get()

	ctorArgs := []string{FnRemoveAdditionalKey, user.AddressBase58Check, base58additionalKey, nc}
	validatorMultisignedUser := &mocks.UserFoundationMultisigned{
		UserID: "multisigned validators",
		Users:  validators,
	}

	pKeys, sMsgsByte, err := validatorMultisignedUser.Sign(ctorArgs...)
	Expect(err).NotTo(HaveOccurred())

	sMsgsStr := make([]string, 0, len(sMsgsByte))
	for _, sMsgByte := range sMsgsByte {
		sMsgsStr = append(sMsgsStr, hex.EncodeToString(sMsgByte))
	}

	ctorArgs = append(append(ctorArgs, pKeys...), sMsgsStr...)

	sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelACL,
		Orderer:   ts.Network.OrdererAddress(ts.Orderer, nwo.ListenPort),
		Name:      cmn.ChannelACL,
		Ctor:      cmn.CtorFromSlice(ctorArgs),
		PeerAddresses: []string{
			ts.Network.PeerAddress(ts.Network.Peer(ts.Org1Name, ts.Peer.Name), nwo.ListenPort),
			ts.Network.PeerAddress(ts.Network.Peer(ts.Org2Name, ts.Peer.Name), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, ts.Network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	ts.CheckAdditionalKey(user, base58additionalKey, false)
}

func (ts *ACLTestSuite) CheckAdditionalKey(user *mocks.UserFoundation, base58additionalKey string, shouldExists bool) {
	Eventually(func() string {
		sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeQuery{
			ChannelID: cmn.ChannelACL,
			Name:      cmn.ChannelACL,
			Ctor:      cmn.CtorFromSlice([]string{"checkKeys", user.PublicKeyBase58}),
		})
		Eventually(sess, ts.Network.EventuallyTimeout).Should(gexec.Exit())
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s, %v", sess.ExitCode(), string(sess.Err.Contents()), err)
		}

		out := sess.Out.Contents()[:len(sess.Out.Contents())-1] // skip line feed
		resp := &pb.AclResponse{}
		err = proto.Unmarshal(out, resp)
		if err != nil {
			return fmt.Sprintf("failed to unmarshal response: %v", err)
		}

		additionalKeys := resp.GetAddress().GetAdditionalKeys()
		keyFound := false
		for _, key := range additionalKeys {
			if key.GetPublicKeyBase58() == base58additionalKey {
				keyFound = true
				break
			}
		}
		switch shouldExists {
		case true:
			if !keyFound {
				return fmt.Sprintf("Error: additional key %s not added", base58additionalKey)
			}
		case false:
			if keyFound {
				return fmt.Sprintf("Error: additional key %s not removed", base58additionalKey)
			}
		}

		return ""
	}, ts.Network.EventuallyTimeout, time.Second).Should(BeEmpty())
}
