package fabricnetwork

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/anoideaopen/acl/tests/integration/cmn"
	"github.com/anoideaopen/acl/tests/integration/cmn/client"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/integration/channelparticipation"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	ginkgomon "github.com/tedsuo/ifrit/ginkgomon_v2"
	"github.com/tedsuo/ifrit/grouper"
)

func CheckResult(successF func(out []byte) string, errorF func(outErr []byte) string) client.CheckResultFunc {
	return func(err error, sessExitCode int, sessError []byte, sessOut []byte) string {
		if (successF == nil && errorF == nil) ||
			(successF != nil && errorF != nil) {
			return "error: only one function must be defined"
		}

		if err != nil {
			return fmt.Sprintf("error executing command: %v", err)
		}

		if successF != nil {
			if sessExitCode != 0 {
				return fmt.Sprintf("exit code is %d: %s, %v", sessExitCode, string(sessError), err)
			}
			out := sessOut[:len(sessOut)-1] // skip line feed
			return successF(out)
		}

		if sessExitCode == 0 {
			return fmt.Sprintf("exit code is %d", sessExitCode)
		}

		return errorF(sessError)
	}
}

func CheckBalance(etalon string) func([]byte) string {
	return func(out []byte) string {
		etl := "\"" + etalon + "\""
		if string(out) != etl {
			return "not equal " + string(out) + " and " + etl
		}
		return ""
	}
}

func PeerGroupRunners(n *nwo.Network) (ifrit.Runner, []*ginkgomon.Runner) {
	var runners []*ginkgomon.Runner
	members := grouper.Members{}
	for _, p := range n.Peers {
		peerRunner := n.PeerRunner(p, "FABRIC_LOGGING_SPEC=debug:grpc=debug")
		members = append(members, grouper.Member{Name: p.ID(), Runner: peerRunner})
		runners = append(runners, peerRunner)
	}
	return grouper.NewParallel(syscall.SIGTERM, members), runners
}

func JoinChannel(network *nwo.Network, channel string, onlyNodes ...int) {
	genesisBlockBytes, err := os.ReadFile(network.OutputBlockPath(channel))
	if err != nil && errors.Is(err, syscall.ENOENT) {
		sess, err := network.ConfigTxGen(commands.OutputBlock{
			ChannelID:   channel,
			Profile:     network.Profiles[0].Name,
			ConfigPath:  network.RootDir,
			OutputBlock: network.OutputBlockPath(channel),
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))

		genesisBlockBytes, err = os.ReadFile(network.OutputBlockPath(channel))
		Expect(err).NotTo(HaveOccurred())
	}

	genesisBlock := &common.Block{}
	err = proto.Unmarshal(genesisBlockBytes, genesisBlock)
	Expect(err).NotTo(HaveOccurred())

	expectedChannelInfoPT := channelparticipation.ChannelInfo{
		Name:              channel,
		URL:               "/participation/v1/channels/" + channel,
		Status:            "active",
		ConsensusRelation: "consenter",
		Height:            1,
	}

	if len(onlyNodes) != 0 {
		for _, i := range onlyNodes {
			o := network.Orderers[i]
			By("joining " + o.Name + " to channel as a consenter")
			channelparticipation.Join(network, o, channel, genesisBlock, expectedChannelInfoPT)
			channelInfo := channelparticipation.ListOne(network, o, channel)
			Expect(channelInfo).To(Equal(expectedChannelInfoPT))
		}

		return
	}

	for _, o := range network.Orderers {
		By("joining " + o.Name + " to channel as a consenter")
		channelparticipation.Join(network, o, channel, genesisBlock, expectedChannelInfoPT)
		channelInfo := channelparticipation.ListOne(network, o, channel)
		Expect(channelInfo).To(Equal(expectedChannelInfoPT))
	}
}

func DeployChaincodeFn(components *nwo.Components, network *nwo.Network, channel string, testDir string) {
	nwo.DeployChaincode(network, channel, network.Orderers[0], nwo.Chaincode{
		Name:            "mycc",
		Version:         "0.0",
		Path:            components.Build("github.com/hyperledger/fabric/integration/chaincode/simple/cmd"),
		Lang:            "binary",
		PackageFile:     filepath.Join(testDir, "simplecc.tar.gz"),
		Ctor:            cmn.CtorFromSlice([]string{"init", "a", "100", "b", "200"}),
		SignaturePolicy: `AND ('Org1MSP.member','Org2MSP.member')`,
		Sequence:        "1",
		InitRequired:    true,
		Label:           "my_prebuilt_chaincode",
	})
}

func InvokeQuery(network *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer, channel string, expectedBalance int) {
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: channel,
		Orderer:   network.OrdererAddress(orderer, nwo.ListenPort),
		Name:      "mycc",
		Ctor:      cmn.CtorFromSlice([]string{"invoke", "a", "b", "10"}),
		PeerAddresses: []string{
			network.PeerAddress(network.Peer("Org1", "peer0"), nwo.ListenPort),
			network.PeerAddress(network.Peer("Org2", "peer0"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	queryExpect(network, peer, channel, "a", expectedBalance)
}

func queryExpect(network *nwo.Network, peer *nwo.Peer, channel string, key string, expectedBalance int) {
	Eventually(func() string {
		sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
			ChannelID: channel,
			Name:      "mycc",
			Ctor:      cmn.CtorFromSlice([]string{"query", key}),
		})
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit())
		if sess.ExitCode() != 0 {
			return fmt.Sprintf("exit code is %d: %s, %v", sess.ExitCode(), string(sess.Err.Contents()), err)
		}

		outStr := strings.TrimSpace(string(sess.Out.Contents()))
		if outStr != fmt.Sprintf("%d", expectedBalance) {
			return fmt.Sprintf("Error: expected: %d, received %s", expectedBalance, outStr)
		}
		return ""
	}, network.EventuallyTimeout, time.Second).Should(BeEmpty())
}
