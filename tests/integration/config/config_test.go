package config

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	aclpb "github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/acl/tests/common"
	aclcmn "github.com/anoideaopen/acl/tests/integration/cmn"
	pbfound "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/anoideaopen/foundation/test/integration/cmn/fabricnetwork"
	"github.com/anoideaopen/foundation/test/integration/cmn/runner"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/fabricconfig"
	runnerFbk "github.com/hyperledger/fabric/integration/nwo/runner"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/tedsuo/ifrit"
	ginkgomon "github.com/tedsuo/ifrit/ginkgomon_v2"
)

var _ = Describe("ACL config tests", func() {
	var (
		testDir          string
		cli              *docker.Client
		network          *nwo.Network
		networkProcess   ifrit.Process
		ordererProcesses []ifrit.Process
		peerProcesses    ifrit.Process
	)

	BeforeEach(func() {
		networkProcess = nil
		ordererProcesses = nil
		peerProcesses = nil
		var err error
		testDir, err = os.MkdirTemp("", "foundation")
		Expect(err).NotTo(HaveOccurred())

		cli, err = docker.NewClientFromEnv()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if networkProcess != nil {
			networkProcess.Signal(syscall.SIGTERM)
			Eventually(networkProcess.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		if peerProcesses != nil {
			peerProcesses.Signal(syscall.SIGTERM)
			Eventually(peerProcesses.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		if network != nil {
			network.Cleanup()
		}
		for _, ordererInstance := range ordererProcesses {
			ordererInstance.Signal(syscall.SIGTERM)
			Eventually(ordererInstance.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		err := os.RemoveAll(testDir)
		Expect(err).NotTo(HaveOccurred())
	})

	var (
		channels       = []string{cmn.ChannelAcl}
		ordererRunners []*ginkgomon.Runner
		redisProcess   ifrit.Process
		redisDB        *runner.RedisDB
		networkFound   *cmn.NetworkFoundation
		peer           *nwo.Peer
		admin          *client.UserFoundation
	)
	BeforeEach(func() {
		By("start redis")
		redisDB = &runner.RedisDB{}
		redisProcess = ifrit.Invoke(redisDB)
		Eventually(redisProcess.Ready(), runnerFbk.DefaultStartTimeout).Should(BeClosed())
		Consistently(redisProcess.Wait()).ShouldNot(Receive())
	})
	AfterEach(func() {
		By("stop redis " + redisDB.Address())
		if redisProcess != nil {
			redisProcess.Signal(syscall.SIGTERM)
			Eventually(redisProcess.Wait(), time.Minute).Should(Receive())
		}
	})
	BeforeEach(func() {
		networkConfig := nwo.MultiNodeSmartBFT()
		networkConfig.Channels = nil

		pchs := make([]*nwo.PeerChannel, 0, cap(channels))
		for _, ch := range channels {
			pchs = append(pchs, &nwo.PeerChannel{
				Name:   ch,
				Anchor: true,
			})
		}
		for _, peer := range networkConfig.Peers {
			peer.Channels = pchs
		}

		network = nwo.New(networkConfig, testDir, cli, StartPort(), components)
		cwd, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())
		network.ExternalBuilders = append(network.ExternalBuilders,
			fabricconfig.ExternalBuilder{
				Path:                 filepath.Join(cwd, ".", "externalbuilders", "binary"),
				Name:                 "binary",
				PropagateEnvironment: []string{"GOPROXY"},
			},
		)

		networkFound = cmn.New(network, channels)
		networkFound.Robot.RedisAddresses = []string{redisDB.Address()}
		networkFound.ChannelTransfer.RedisAddresses = []string{redisDB.Address()}

		networkFound.GenerateConfigTree()
		networkFound.Bootstrap()

		for _, orderer := range network.Orderers {
			runner := network.OrdererRunner(orderer)
			runner.Command.Env = append(runner.Command.Env, "FABRIC_LOGGING_SPEC=orderer.consensus.smartbft=debug:grpc=debug")
			ordererRunners = append(ordererRunners, runner)
			proc := ifrit.Invoke(runner)
			ordererProcesses = append(ordererProcesses, proc)
			Eventually(proc.Ready(), network.EventuallyTimeout).Should(BeClosed())
		}

		peerGroupRunner, _ := fabricnetwork.PeerGroupRunners(network)
		peerProcesses = ifrit.Invoke(peerGroupRunner)
		Eventually(peerProcesses.Ready(), network.EventuallyTimeout).Should(BeClosed())

		By("Joining orderers to channels")
		for _, channel := range channels {
			fabricnetwork.JoinChannel(network, channel)
		}

		By("Waiting for followers to see the leader")
		Eventually(ordererRunners[1].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 1"))
		Eventually(ordererRunners[2].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 1"))
		Eventually(ordererRunners[3].Err(), network.EventuallyTimeout, time.Second).Should(gbytes.Say("Message from 1"))

		By("Joining peers to channels")
		for _, channel := range channels {
			network.JoinChannel(channel, network.Orderers[0], network.PeersWithChannel(channel)...)
		}

		peer = network.Peer("Org1", "peer0")

		admin, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		Expect(admin.PrivateKeyBytes).NotTo(Equal(nil))
	})

	It("Acl init wrong admin ski format", func() {
		By("Deploying chaincode acl")
		aclCfg := &aclpb.ACLConfig{
			AdminSKIEncoded: "a",
			Validators: []*aclpb.ACLValidator{
				{
					PublicKey: "0",
					KeyType:   common.KeyTypeEd25519,
				},
			},
		}
		aclcmn.DeployACLWithError(network, components, testDir, aclCfg, `'adminSKI' (index of args 0) is invalid - format found 'a' but expected hex encoded string`)
	})

	It("Acl init empty admin ski", func() {
		By("Deploying chaincode acl")
		aclCfg := &aclpb.ACLConfig{
			AdminSKIEncoded: "",
			Validators: []*aclpb.ACLValidator{
				{
					PublicKey: "0",
					KeyType:   common.KeyTypeEd25519,
				},
			},
		}
		aclcmn.DeployACLWithError(network, components, testDir, aclCfg, `'adminSKI' is empty`)
	})

	It("Acl init empty validators", func() {
		By("Deploying chaincode acl")
		pathToPrivateKeyBackend := network.PeerUserKey(peer, "User1")
		skiBackend, err := cmn.ReadSKI(pathToPrivateKeyBackend)
		Expect(err).NotTo(HaveOccurred())

		aclCfg := &aclpb.ACLConfig{
			AdminSKIEncoded: skiBackend,
			Validators:      []*aclpb.ACLValidator{},
		}
		aclcmn.DeployACLWithError(network, components, testDir, aclCfg, `validators are not set`)
	})

	It("Acl init empty validator", func() {
		By("Deploying chaincode acl")
		pathToPrivateKeyBackend := network.PeerUserKey(peer, "User1")
		skiBackend, err := cmn.ReadSKI(pathToPrivateKeyBackend)
		Expect(err).NotTo(HaveOccurred())

		aclCfg := &aclpb.ACLConfig{
			AdminSKIEncoded: skiBackend,
			Validators: []*aclpb.ACLValidator{
				{
					PublicKey: "",
					KeyType:   common.KeyTypeEd25519,
				},
				{
					PublicKey: admin.PublicKeyBase58,
					KeyType:   common.KeyTypeEd25519,
				},
			},
		}
		aclcmn.DeployACLWithError(network, components, testDir, aclCfg, `'validator #'0'' is empty`)
	})

	It("Acl init validator duplicated", func() {
		By("Deploying chaincode acl")
		pathToPrivateKeyBackend := network.PeerUserKey(peer, "User1")
		skiBackend, err := cmn.ReadSKI(pathToPrivateKeyBackend)
		Expect(err).NotTo(HaveOccurred())

		aclCfg := &aclpb.ACLConfig{
			AdminSKIEncoded: skiBackend,
			Validators: []*aclpb.ACLValidator{
				{
					PublicKey: admin.PublicKeyBase58,
					KeyType:   common.KeyTypeEd25519,
				},
				{
					PublicKey: admin.PublicKeyBase58,
					KeyType:   common.KeyTypeEd25519,
				},
			},
		}
		aclcmn.DeployACLWithError(network, components, testDir, aclCfg, `'validator #'1'' is duplicated`)
	})

	It("Acl init invalid key type", func() {
		By("Deploying chaincode acl")
		pathToPrivateKeyBackend := network.PeerUserKey(peer, "User1")
		skiBackend, err := cmn.ReadSKI(pathToPrivateKeyBackend)
		Expect(err).NotTo(HaveOccurred())

		aclCfg := &aclpb.ACLConfig{
			AdminSKIEncoded: skiBackend,
			Validators: []*aclpb.ACLValidator{
				{
					PublicKey: admin.PublicKeyBase58,
					KeyType:   "fhdsjkaghfjkahfgk",
				},
			},
		}
		aclcmn.DeployACLWithError(network, components, testDir, aclCfg, `'validator #'0'' has invalid key type:`)
	})

	It("Acl init gost key type", func() {
		By("Deploying chaincode acl")
		pathToPrivateKeyBackend := network.PeerUserKey(peer, "User1")
		skiBackend, err := cmn.ReadSKI(pathToPrivateKeyBackend)
		Expect(err).NotTo(HaveOccurred())

		aclCfg := &aclpb.ACLConfig{
			AdminSKIEncoded: skiBackend,
			Validators: []*aclpb.ACLValidator{
				{
					PublicKey: admin.PublicKeyBase58,
					KeyType:   "gost",
				},
			},
		}
		aclcmn.DeployACLWithError(network, components, testDir, aclCfg, `'validator #'0'' has invalid key type:`)
	})
})
