package cmn

import (
	"path/filepath"

	aclpb "github.com/anoideaopen/acl/proto"
	pb "github.com/anoideaopen/foundation/proto"
	industrialtoken "github.com/anoideaopen/foundation/test/chaincode/industrial/industrial_token"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	ChannelAcl        = "acl"
	ChannelCC         = "cc"
	ChannelFiat       = "fiat"
	ChannelIndustrial = "industrial"
)

func DeployACL(network *nwo.Network, components *nwo.Components, peer *nwo.Peer,
	testDir string, skiBackend string, publicKeyBase58 string) {
	By("Deploying chaincode acl")
	aclCfg := &aclpb.ACLConfig{
		AdminSKIEncoded: skiBackend,
		Validators:      []string{publicKeyBase58},
	}
	cfgBytesACL, err := protojson.Marshal(aclCfg)
	Expect(err).NotTo(HaveOccurred())
	ctorACL := CtorFromSlice([]string{string(cfgBytesACL)})
	DeployChaincodeFoundation(network, ChannelAcl, components,
		AclModulePath(), ctorACL, testDir)

	By("querying the chaincode from acl")
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
		ChannelID: ChannelAcl,
		Name:      ChannelAcl,
		Ctor:      CtorFromSlice([]string{"getAddresses", "10", ""}),
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Eventually(sess, network.EventuallyTimeout).Should(gbytes.Say(`{"Addrs":null,"Bookmark":""}`))
}

func DeployCC(network *nwo.Network, components *nwo.Components, peer *nwo.Peer,
	testDir string, skiRobot string, addressBase58Check string) {
	By("Deploying chaincode cc")
	cfgCC := &pb.Config{
		Contract: &pb.ContractConfig{Symbol: "CC", RobotSKI: skiRobot,
			Admin: &pb.Wallet{Address: addressBase58Check}},
		Token: &pb.TokenConfig{Name: "Currency Coin", Decimals: 8,
			UnderlyingAsset: "US Dollars", Issuer: &pb.Wallet{Address: addressBase58Check}},
	}
	cfgBytesCC, err := protojson.Marshal(cfgCC)
	Expect(err).NotTo(HaveOccurred())
	ctorCC := CtorFromSlice([]string{string(cfgBytesCC)})
	DeployChaincodeFoundation(network, ChannelCC, components,
		CcModulePath(), ctorCC, testDir)

	By("querying the chaincode from cc")
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
		ChannelID: ChannelCC,
		Name:      ChannelCC,
		Ctor:      CtorFromSlice([]string{"metadata"}),
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Eventually(sess, network.EventuallyTimeout).Should(gbytes.Say(`{"name":"Currency Coin","symbol":"CC","decimals":8,"underlying_asset":"US Dollars"`))
}

func DeployFiat(network *nwo.Network, components *nwo.Components, peer *nwo.Peer,
	testDir string, skiRobot string, adminAddressBase58Check string,
	feeSetterAddressBase58Check string, feeAddressSetterAddressBase58Check string) {
	By("Deploying chaincode fiat")

	cfgFiat := &pb.Config{
		Contract: &pb.ContractConfig{
			Symbol:   "FIAT",
			RobotSKI: skiRobot,
			Admin:    &pb.Wallet{Address: adminAddressBase58Check},
			Options: &pb.ChaincodeOptions{
				DisabledFunctions: []string{"TxBuyToken", "TxBuyBack"},
			},
		},
		Token: &pb.TokenConfig{
			Name:             "FIAT",
			Decimals:         8,
			UnderlyingAsset:  "US Dollars",
			Issuer:           &pb.Wallet{Address: adminAddressBase58Check},
			FeeSetter:        &pb.Wallet{Address: feeSetterAddressBase58Check},
			FeeAddressSetter: &pb.Wallet{Address: feeAddressSetterAddressBase58Check},
		},
	}
	cfgBytesFiat, err := protojson.Marshal(cfgFiat)
	Expect(err).NotTo(HaveOccurred())
	ctorFiat := CtorFromSlice([]string{string(cfgBytesFiat)})
	DeployChaincodeFoundation(network, ChannelFiat, components,
		FiatModulePath(), ctorFiat, testDir)

	By("querying the chaincode from fiat")
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
		ChannelID: ChannelFiat,
		Name:      ChannelFiat,
		Ctor:      CtorFromSlice([]string{"metadata"}),
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Eventually(sess, network.EventuallyTimeout).Should(gbytes.Say(`{"name":"FIAT","symbol":"FIAT","decimals":8,"underlying_asset":"US Dollars"`))
}

func DeployIndustrial(network *nwo.Network, components *nwo.Components, peer *nwo.Peer,
	testDir string, skiRobot string, adminAddressBase58Check string,
	feeSetterAddressBase58Check string, feeAddressSetterAddressBase58Check string) {
	extCfg := industrialtoken.ExtConfig{
		Name:             "Industrial token",
		Decimals:         8,
		UnderlyingAsset:  "TEST_UnderlyingAsset",
		DeliveryForm:     "TEST_DeliveryForm",
		UnitOfMeasure:    "TEST_IT",
		TokensForUnit:    "1",
		PaymentTerms:     "Non-prepaid",
		Price:            "Floating",
		Issuer:           &pb.Wallet{Address: adminAddressBase58Check},
		FeeSetter:        &pb.Wallet{Address: feeSetterAddressBase58Check},
		FeeAddressSetter: &pb.Wallet{Address: feeAddressSetterAddressBase58Check},
	}
	cfgIndustrial := &pb.Config{
		Contract: &pb.ContractConfig{
			Symbol:   "INDUSTRIAL",
			RobotSKI: skiRobot,
			Admin:    &pb.Wallet{Address: adminAddressBase58Check},
		},
	}
	cfgIndustrial.ExtConfig, _ = anypb.New(&extCfg)

	cfgBytesIndustrial, err := protojson.Marshal(cfgIndustrial)
	Expect(err).NotTo(HaveOccurred())
	ctorIndustrial := CtorFromSlice([]string{string(cfgBytesIndustrial)})
	By("Deploying chaincode industrial")
	DeployChaincodeFoundation(network, ChannelIndustrial, components,
		IndustrialModulePath(), ctorIndustrial, testDir)

	By("querying the chaincode from industrial")
	sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
		ChannelID: ChannelIndustrial,
		Name:      ChannelIndustrial,
		Ctor:      CtorFromSlice([]string{"metadata"}),
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
	Eventually(sess, network.EventuallyTimeout).Should(gbytes.Say(`{"name":"Industrial token","symbol":"INDUSTRIAL","decimals":8,"underlying_asset":"TEST_UnderlyingAsset"`))
}

func DeployChaincodeFoundation(
	network *nwo.Network,
	channel string,
	components *nwo.Components,
	path string,
	ctor string,
	testDir string,
) {
	DeployChaincode(network, channel, network.Orderers[0], nwo.Chaincode{
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
	})
}

// DeployChaincode is a helper that will install chaincode to all peers that
// are connected to the specified channel, approve the chaincode on one of the
// peers of each organization in the network, commit the chaincode definition
// on the channel using one of the peers, and wait for the chaincode commit to
// complete on all of the peers. It uses the _lifecycle implementation.
// NOTE V2_0 capabilities must be enabled for this functionality to work.
func DeployChaincode(n *nwo.Network, channel string, orderer *nwo.Orderer, chaincode nwo.Chaincode, peers ...*nwo.Peer) {
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
		InitChaincode(n, channel, orderer, chaincode, peers...)
	}
}

func InitChaincode(n *nwo.Network, channel string, orderer *nwo.Orderer, chaincode nwo.Chaincode, peers ...*nwo.Peer) {
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
	Eventually(sess, n.EventuallyTimeout).Should(gexec.Exit(0))
	for i := 0; i < len(peerAddresses); i++ {
		Eventually(sess.Err, n.EventuallyTimeout).Should(gbytes.Say(`\Qcommitted with status (VALID)\E`))
	}
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))
}
