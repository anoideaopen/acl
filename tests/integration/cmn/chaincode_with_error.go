package cmn

import (
	"path/filepath"

	aclpb "github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"google.golang.org/protobuf/encoding/protojson"
)

func DeployACLWithError(
	network *nwo.Network,
	components *nwo.Components,
	testDir string,
	aclCfg *aclpb.ACLConfig,
	errorMsg string,
) {
	By("Deploying chaincode acl")
	cfgBytesACL, err := protojson.Marshal(aclCfg)
	Expect(err).NotTo(HaveOccurred())
	ctorACL := cmn.CtorFromSlice([]string{string(cfgBytesACL)})
	DeployChaincodeFoundationWithError(network, cmn.ChannelAcl, components,
		cmn.AclModulePath(), ctorACL, testDir, errorMsg)
}

func DeployChaincodeFoundationWithError(
	network *nwo.Network,
	channel string,
	components *nwo.Components,
	path string,
	ctor string,
	testDir string,
	errorMsg string,
) {
	DeployChaincodeWithError(network, channel, network.Orderers[0],
		nwo.Chaincode{
			Name:            channel,
			Version:         "0.0",
			Path:            components.Build(path),
			Lang:            "binary",
			PackageFile:     filepath.Join(testDir, channel+".tar.gz"),
			Ctor:            ctor,
			SignaturePolicy: `AND ('Org1MSP.member','Org2MSP.member')`,
			Sequence:        "1",
			InitRequired:    true,
			Label:           "my_prebuilt_chaincode",
		},
		[]*nwo.Peer{},
		errorMsg,
	)
}

// DeployChaincodeWithError is a helper that will install chaincode to all peers that
// are connected to the specified channel, approve the chaincode on one of the
// peers of each organization in the network, commit the chaincode definition
// on the channel using one of the peers, and wait for the chaincode commit to
// complete on all the peers. It uses the _lifecycle implementation.
// NOTE V2_0 capabilities must be enabled for this functionality to work.
func DeployChaincodeWithError(n *nwo.Network, channel string, orderer *nwo.Orderer, chaincode nwo.Chaincode, peers []*nwo.Peer, errorMsg string) {
	if len(peers) == 0 {
		peers = n.PeersWithChannel(channel)
	}
	if len(peers) == 0 {
		return
	}

	nwo.PackageAndInstallChaincode(n, chaincode, peers...)

	// approve for each org
	nwo.ApproveChaincodeForMyOrg(n, channel, orderer, chaincode, peers...)

	// wait for checkcommitreadiness returns ready status
	nwo.CheckCommitReadinessUntilReady(n, channel, chaincode, n.PeerOrgs(), peers...)

	// after the chaincode definition has been correctly approved for each org,
	// demonstrate the capability to inspect the discrepancies in the chaincode definitions
	// by executing checkcommitreadiness with inspect flag,
	// with intentionally altered values for chaincode definition parameters
	nwo.InspectChaincodeDiscrepancies(n, channel, chaincode, n.PeerOrgs(), peers...)

	// commit definition
	nwo.CommitChaincode(n, channel, orderer, chaincode, peers[0], peers...)

	// init the chaincode, if required
	if chaincode.InitRequired {
		InitChaincodeWithError(n, channel, orderer, chaincode, peers, errorMsg)
	}
}

func InitChaincodeWithError(n *nwo.Network, channel string, orderer *nwo.Orderer, chaincode nwo.Chaincode, peers []*nwo.Peer, errorMsg string) {
	// init using one peer per org
	initOrgs := map[string]bool{}
	var peerAddresses []string
	for _, p := range peers {
		if exists := initOrgs[p.Organization]; !exists {
			peerAddresses = append(peerAddresses, n.PeerAddress(p, nwo.ListenPort))
			initOrgs[p.Organization] = true
		}
	}

	sess, err := n.PeerAdminSession(peers[0], commands.ChaincodeInvoke{
		ChannelID:     channel,
		Orderer:       n.OrdererAddress(orderer, nwo.ListenPort),
		Name:          chaincode.Name,
		Ctor:          chaincode.Ctor,
		PeerAddresses: peerAddresses,
		WaitForEvent:  true,
		IsInit:        true,
		ClientAuth:    n.ClientAuthRequired,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, n.EventuallyTimeout).Should(gexec.Exit(1))
	Expect(sess.Err.Contents()).To(ContainSubstring(errorMsg))
}
