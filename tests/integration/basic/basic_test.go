package basic

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	aclcmn "github.com/anoideaopen/acl/tests/integration/cmn"
	aclclient "github.com/anoideaopen/acl/tests/integration/cmn/client"
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

// Functions names
const (
	FnCheckKeys    = "checkKeys"
	FnCheckAddress = "checkAddress"
	FnGetAddresses = "getAddresses"

	usersPolicy = 3
)

var _ = Describe("ACL basic tests", func() {
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
		skiBackend       string
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

		admin, err = client.NewUserFoundation(pbfound.KeyType_secp256k1)
		Expect(err).NotTo(HaveOccurred())
		Expect(admin.PrivateKeyBytes).NotTo(Equal(nil))

		feeSetter, err = client.NewUserFoundation(pbfound.KeyType_secp256k1)
		Expect(err).NotTo(HaveOccurred())
		Expect(feeSetter.PrivateKeyBytes).NotTo(Equal(nil))

		feeAddressSetter, err = client.NewUserFoundation(pbfound.KeyType_secp256k1)
		Expect(err).NotTo(HaveOccurred())
		Expect(feeAddressSetter.PrivateKeyBytes).NotTo(Equal(nil))

		cmn.DeployACL(network, components, peer, testDir, skiBackend, admin.PublicKeyBase58, admin.KeyType)
	})

	It("Add user test & check keys test", func() {
		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		client.AddUser(network, peer, network.Orderers[0], user)

		By("checking result")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, user), nil), FnCheckKeys, user.PublicKeyBase58)
	})

	It("Add multisigned user test", func() {
		By("creating multisgined user")
		user1, err := client.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
		Expect(err).NotTo(HaveOccurred())

		By("adding users to ACL")
		for _, user := range user1.Users {
			client.AddUser(network, peer, network.Orderers[0], user)
		}

		By("adding multisigned user")
		client.AddUserMultisigned(network, peer, network.Orderers[0], usersPolicy, user1)

		// ToDo add check multisigned user
	})

	It("Change public key with hex encoded key", func() {
		By("add admin to acl")
		client.AddUser(network, peer, network.Orderers[0], admin)

		By("creating users")
		oldUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		newUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		By("adding old user to ACL")
		client.AddUser(network, peer, network.Orderers[0], oldUser)

		By("adding new user to ACL")
		client.AddUser(network, peer, network.Orderers[0], newUser)

		By("changing user public key")
		aclclient.ChangePublicKey(network, peer, network.Orderers[0], oldUser, newUser.PublicKeyBase58, "0", "0", admin)

		By("checking result")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser), nil), FnCheckKeys, newUser.PublicKeyBase58)
	})

	It("Change public key with base58 signature test", func() {
		By("add admin to acl")
		client.AddUser(network, peer, network.Orderers[0], admin)

		By("creating users")
		oldUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		newUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		By("adding old user to ACL")
		client.AddUser(network, peer, network.Orderers[0], oldUser)

		By("adding new user to ACL")
		client.AddUser(network, peer, network.Orderers[0], newUser)

		By("changing user public key")
		aclclient.ChangePublicKeyBase58signed(network, peer, network.Orderers[0], oldUser, "0", cmn.ChannelAcl, cmn.ChannelAcl, newUser.PublicKeyBase58, "reason", "0", admin)

		By("checking result")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser), nil), FnCheckKeys, newUser.PublicKeyBase58)
	})

	It("Change multisigned user public key", func() {
		By("add admin to acl")
		client.AddUser(network, peer, network.Orderers[0], admin)

		By("creating multisigned user")
		multisignedUser, err := client.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
		Expect(err).NotTo(HaveOccurred())

		By("adding users to ACL")
		for _, user := range multisignedUser.Users {
			client.AddUser(network, peer, network.Orderers[0], user)
		}

		By("adding multisigned user")
		client.AddUserMultisigned(network, peer, network.Orderers[0], usersPolicy, multisignedUser)

		By("creating new user for multisigned")
		newUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		By("adding new user to ACL")
		client.AddUser(network, peer, network.Orderers[0], newUser)

		By("replacing old user to new in multisigned Users collection")
		oldUser := multisignedUser.Users[0]
		multisignedUser.Users = slices.Replace(multisignedUser.Users, 0, 1, newUser)

		By("changing multisigned user public key")
		client.ChangeMultisigPublicKey(network, peer, network.Orderers[0], multisignedUser, oldUser.PublicKeyBase58, newUser.PublicKeyBase58, "reason", "0", admin)

		// ToDo add check for getting the old address providing the new key
	})

	It("Check address test", func() {
		By("add admin to acl")
		client.AddUser(network, peer, network.Orderers[0], admin)

		By("creating user")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		By("adding old user to ACL")
		client.AddUser(network, peer, network.Orderers[0], user)

		By("checking address")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckAddress(user), nil), FnCheckAddress, user.AddressBase58Check)

		By("add user to gray list")
		aclclient.AddToGrayList(network, peer, network.Orderers[0], user)

		By("checking address")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(nil, aclcmn.CheckAddressGraylisted(user.AddressBase58Check+"is graylisted")), FnCheckAddress, user.AddressBase58Check)
	})

	It("Get Addresses test", func() {
		By("adding users to acl")
		user1, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		user2, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		user3, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		client.AddUser(network, peer, network.Orderers[0], user1)
		client.AddUser(network, peer, network.Orderers[0], user2)
		client.AddUser(network, peer, network.Orderers[0], user3)

		By("checking users")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckAddresses(user1, user2, user3), nil), FnGetAddresses, "100", "")
	})
})
