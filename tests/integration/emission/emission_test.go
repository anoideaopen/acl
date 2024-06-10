package emission

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	aclclient "github.com/anoideaopen/acl/tests/integration/cmn/client"
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

var _ = Describe("ACL emission tests", func() {
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
		channels         = []string{cmn.ChannelAcl, cmn.ChannelFiat}
		ordererRunners   []*ginkgomon.Runner
		redisProcess     ifrit.Process
		redisDB          *runner.RedisDB
		networkFound     *cmn.NetworkFoundation
		peer             *nwo.Peer
		robotProc        ifrit.Process
		skiBackend       string
		skiRobot         string
		admin            *client.UserFoundation
		user             *client.UserFoundation
		feeSetter        *client.UserFoundation
		feeAddressSetter *client.UserFoundation
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

		pathToPrivateKeyBackend := network.PeerUserKey(peer, "User1")
		skiBackend, err = cmn.ReadSKI(pathToPrivateKeyBackend)
		Expect(err).NotTo(HaveOccurred())

		pathToPrivateKeyRobot := network.PeerUserKey(peer, "User2")
		skiRobot, err = cmn.ReadSKI(pathToPrivateKeyRobot)
		Expect(err).NotTo(HaveOccurred())

		admin = client.NewUserFoundation()
		Expect(admin.PrivateKey).NotTo(Equal(nil))
		feeSetter = client.NewUserFoundation()
		Expect(feeSetter.PrivateKey).NotTo(Equal(nil))
		feeAddressSetter = client.NewUserFoundation()
		Expect(feeAddressSetter.PrivateKey).NotTo(Equal(nil))

		cmn.DeployACL(network, components, peer, testDir, skiBackend, admin.PublicKeyBase58)
	})
	BeforeEach(func() {
		By("start robot")
		robotRunner := networkFound.RobotRunner()
		robotProc = ifrit.Invoke(robotRunner)
		Eventually(robotProc.Ready(), network.EventuallyTimeout).Should(BeClosed())
	})
	AfterEach(func() {
		By("stop robot")
		if robotProc != nil {
			robotProc.Signal(syscall.SIGTERM)
			Eventually(robotProc.Wait(), network.EventuallyTimeout).Should(Receive())
		}
	})

	It("Emit transfer test", func() {
		By("add admin to acl")
		client.AddUser(network, peer, network.Orderers[0], admin)

		By("add user to acl")
		user = client.NewUserFoundation()
		client.AddUser(network, peer, network.Orderers[0], user)

		By("deploying fiat channel")
		cmn.DeployFiat(network, components, peer, testDir, skiRobot,
			admin.AddressBase58Check, feeSetter.AddressBase58Check, feeAddressSetter.AddressBase58Check)

		By("emit tokens")
		emitAmount := "1000"
		client.TxInvokeWithSign(network, peer, network.Orderers[0],
			cmn.ChannelFiat, cmn.ChannelFiat, admin,
			"emit", "", client.NewNonceByTime().Get(), user.AddressBase58Check, emitAmount)

		By("emit check")
		client.Query(network, peer, cmn.ChannelFiat, cmn.ChannelFiat,
			fabricnetwork.CheckResult(fabricnetwork.CheckBalance(emitAmount), nil),
			"balanceOf", user.AddressBase58Check)
	})

	It("Multisigned emit transfer test", func() {
		By("add admin to acl")
		client.AddUser(network, peer, network.Orderers[0], admin)

		By("creating multisigned user")
		const usersPolicy = 3
		multisigUser := aclclient.NewUserFoundationMultisigned(usersPolicy)

		By("adding users to ACL")
		for _, user := range multisigUser.Users {
			client.AddUser(network, peer, network.Orderers[0], user)
		}

		By("adding multisign")
		aclclient.AddMultisig(network, peer, network.Orderers[0], usersPolicy, multisigUser)

		By("deploying fiat channel")
		cmn.DeployFiat(network, components, peer, testDir, skiRobot,
			multisigUser.AddressBase58Check, feeSetter.AddressBase58Check, feeAddressSetter.AddressBase58Check)

		By("add user to acl")
		user = client.NewUserFoundation()
		client.AddUser(network, peer, network.Orderers[0], user)

		By("emit tokens")
		emitAmount := "1000"
		aclclient.TxInvokeWithMultisign(network, peer, network.Orderers[0],
			cmn.ChannelFiat, cmn.ChannelFiat, multisigUser,
			"emit", "", client.NewNonceByTime().Get(), user.AddressBase58Check, emitAmount)

		By("emit check")
		client.Query(network, peer, cmn.ChannelFiat, cmn.ChannelFiat,
			fabricnetwork.CheckResult(fabricnetwork.CheckBalance(emitAmount), nil),
			"balanceOf", user.AddressBase58Check)
	})

	It("Multisig change pub key test", func() {
		By("add admin to acl")
		client.AddUser(network, peer, network.Orderers[0], admin)

		By("creating multisigned user")
		const usersPolicy = 3
		multisigUser := aclclient.NewUserFoundationMultisigned(usersPolicy)

		By("adding users to ACL")
		for _, user := range multisigUser.Users {
			client.AddUser(network, peer, network.Orderers[0], user)
		}

		By("adding multisign")
		aclclient.AddMultisig(network, peer, network.Orderers[0], usersPolicy, multisigUser)

		By("deploying fiat channel")
		cmn.DeployFiat(network, components, peer, testDir, skiRobot,
			multisigUser.AddressBase58Check, feeSetter.AddressBase58Check, feeAddressSetter.AddressBase58Check)

		By("creating new user for multisig")
		newUser := client.NewUserFoundation()

		By("adding new user to ACL")
		client.AddUser(network, peer, network.Orderers[0], newUser)

		By("replacing old user to new in multisigned Users collection")
		oldUser := multisigUser.Users[0]
		multisigUser.Users = slices.Replace(multisigUser.Users, 0, 1, newUser)

		By("changing multisigned user public key")
		aclclient.ChangeMultisigPublicKey(network, peer, network.Orderers[0], multisigUser, oldUser.PublicKeyBase58, newUser.PublicKeyBase58, "reason", "0", admin)

		By("add user to acl")
		user = client.NewUserFoundation()
		client.AddUser(network, peer, network.Orderers[0], user)

		By("emit tokens")
		emitAmount := "1000"
		aclclient.TxInvokeWithMultisign(network, peer, network.Orderers[0],
			cmn.ChannelFiat, cmn.ChannelFiat, multisigUser,
			"emit", "", client.NewNonceByTime().Get(), user.AddressBase58Check, emitAmount)

		By("emit check")
		client.Query(network, peer, cmn.ChannelFiat, cmn.ChannelFiat,
			fabricnetwork.CheckResult(fabricnetwork.CheckBalance(emitAmount), nil),
			"balanceOf", user.AddressBase58Check)
	})
})
