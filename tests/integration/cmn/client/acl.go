package client

import (
	"fmt"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	fclient "github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"google.golang.org/protobuf/encoding/protojson"
	"time"
)

type AclTestSuite struct {
	*fclient.FoundationTestSuite
}

func NewTestSuite(components *nwo.Components) *AclTestSuite {
	return &AclTestSuite{FoundationTestSuite: fclient.NewTestSuite(components)}
}

func (ts *AclTestSuite) CheckAddressForNominee(
	channelName string,
	chaincodeName string,
	nominee *fclient.UserFoundation,
	principal *fclient.UserFoundation,
	haveRight bool,
) {
	Eventually(func() string {
		sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeQuery{
			ChannelID: cmn.ChannelAcl,
			Name:      cmn.ChannelAcl,
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

		Expect(resp.HaveRight).To(BeEquivalentTo(haveRight))

		return ""
	}, ts.Network.EventuallyTimeout, time.Second).Should(BeEmpty())
}

func (ts *AclTestSuite) AddAddressForNominee(
	channelName string,
	chaincodeName string,
	nominee *fclient.UserFoundation,
	principal *fclient.UserFoundation,
) {
	sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelAcl,
		Orderer:   ts.Network.OrdererAddress(ts.Orderer, nwo.ListenPort),
		Name:      cmn.ChannelAcl,
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

func (ts *AclTestSuite) RemoveAddressFromNominee(
	channelName string,
	chaincodeName string,
	nominee *fclient.UserFoundation,
	principal *fclient.UserFoundation,
) {
	sess, err := ts.Network.PeerUserSession(ts.Peer, ts.MainUserName, commands.ChaincodeInvoke{
		ChannelID: cmn.ChannelAcl,
		Orderer:   ts.Network.OrdererAddress(ts.Orderer, nwo.ListenPort),
		Name:      cmn.ChannelAcl,
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
