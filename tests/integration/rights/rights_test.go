package rights

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

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

// Functions names
const (
	FnGetAccountOperationRight = "getAccountOperationRight"
	FnGetAccountAllRights      = "getAccountAllRights"
	FnGetOperationAllRights    = "getOperationAllRights"
)

var _ = Describe("ACL integration rights tests", func() {
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

	It("Add rights test", func() {
		var (
			channelName   = cmn.ChannelAcl
			chaincodeName = cmn.ChannelAcl
			roleName      = "roleName"
			operationName = "operationName"
		)

		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		client.AddUser(network, peer, network.Orderers[0], user)

		etalonRights := []*pbfound.Right{
			{
				ChannelName:   channelName,
				ChaincodeName: chaincodeName,
				RoleName:      roleName,
				OperationName: operationName,
				HaveRight:     aclcmn.TestHaveRight,
			},
		}

		etalonOperationHaveRights := &pbfound.OperationRights{
			OperationName: operationName,
			Rights:        etalonRights,
		}

		By("adding right")
		client.AddRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountAllRights(etalonRights, user), nil), FnGetAccountAllRights, user.AddressBase58Check)

		By("checking getAccountOperationRight")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveRight), nil), FnGetAccountOperationRight, channelName, chaincodeName, roleName, operationName, user.AddressBase58Check)

		By("checking getOperationAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetOperationAllRights(etalonOperationHaveRights, user), nil), FnGetOperationAllRights, channelName, chaincodeName, roleName, operationName)

		By("removing right")
		client.RemoveRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)
		etalonRights = nil
		etalonOperationHaveRights.Rights = nil

		By("checking getAccountOperationRight")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveNoRight), nil), FnGetAccountOperationRight, channelName, chaincodeName, roleName, operationName, user.AddressBase58Check)

		By("checking getOperationAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetOperationAllRights(etalonOperationHaveRights, user), nil), FnGetOperationAllRights, channelName, chaincodeName, roleName, operationName)

		By("checking getAccountAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountAllRights(etalonRights, user), nil), FnGetAccountAllRights, user.AddressBase58Check)
	})

	It("Get Account All Rights test", func() {
		var (
			channelName   = cmn.ChannelAcl
			chaincodeName = cmn.ChannelAcl
			roleName      = "roleName"
			operationName = "operationName"
		)

		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		client.AddUser(network, peer, network.Orderers[0], user)

		etalonRights := []*pbfound.Right{
			{
				ChannelName:   channelName,
				ChaincodeName: chaincodeName,
				RoleName:      roleName,
				OperationName: operationName,
				HaveRight:     aclcmn.TestHaveRight,
			},
		}

		By("adding right")
		client.AddRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking result")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountAllRights(etalonRights, user), nil), FnGetAccountAllRights, user.AddressBase58Check)

		By("removing right")
		client.RemoveRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking result")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountAllRights(nil, user), nil), FnGetAccountAllRights, user.AddressBase58Check)
	})

	It("Get Account Operation Right test", func() {
		var (
			channelName   = cmn.ChannelAcl
			chaincodeName = cmn.ChannelAcl
			roleName      = "roleName"
			operationName = "operationName"
		)

		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		client.AddUser(network, peer, network.Orderers[0], user)

		By("adding right")
		client.AddRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountOperationRight")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveRight), nil), FnGetAccountOperationRight, channelName, chaincodeName, roleName, operationName, user.AddressBase58Check)

		By("removing right")
		client.RemoveRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountOperationRight")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveNoRight), nil), FnGetAccountOperationRight, channelName, chaincodeName, roleName, operationName, user.AddressBase58Check)
	})

	It("Get Operation All Rights test", func() {
		var (
			channelName   = cmn.ChannelAcl
			chaincodeName = cmn.ChannelAcl
			roleName      = "roleName"
			operationName = "operationName"
		)

		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		client.AddUser(network, peer, network.Orderers[0], user)

		etalonRights := []*pbfound.Right{
			{
				ChannelName:   channelName,
				ChaincodeName: chaincodeName,
				RoleName:      roleName,
				OperationName: operationName,
				HaveRight:     aclcmn.TestHaveRight,
			},
		}

		etalonOperationHaveRights := &pbfound.OperationRights{
			OperationName: operationName,
			Rights:        etalonRights,
		}

		By("adding right")
		client.AddRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking getOperationAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetOperationAllRights(etalonOperationHaveRights, user), nil), FnGetOperationAllRights, channelName, chaincodeName, roleName, operationName)

		By("removing right")
		client.RemoveRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)
		etalonOperationHaveRights.Rights = nil

		By("checking getOperationAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetOperationAllRights(etalonOperationHaveRights, user), nil), FnGetOperationAllRights, channelName, chaincodeName, roleName, operationName)
	})

	It("Remove rights test", func() {
		var (
			channelName   = cmn.ChannelAcl
			chaincodeName = cmn.ChannelAcl
			roleName      = "roleName"
			operationName = "operationName"
		)

		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		client.AddUser(network, peer, network.Orderers[0], user)

		etalonRights := []*pbfound.Right{
			{
				ChannelName:   channelName,
				ChaincodeName: chaincodeName,
				RoleName:      roleName,
				OperationName: operationName,
				HaveRight:     aclcmn.TestHaveRight,
			},
		}

		By("adding right")
		client.AddRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountAllRights(etalonRights, user), nil), FnGetAccountAllRights, user.AddressBase58Check)

		By("checking getAccountOperationRight")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveRight), nil), FnGetAccountOperationRight, channelName, chaincodeName, roleName, operationName, user.AddressBase58Check)

		By("removing right")
		client.RemoveRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountOperationRight")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveNoRight), nil), FnGetAccountOperationRight, channelName, chaincodeName, roleName, operationName, user.AddressBase58Check)

		By("checking getAccountAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountAllRights(nil, user), nil), FnGetAccountAllRights, user.AddressBase58Check)

		By("removing rights again")
		client.RemoveRights(network, peer, network.Orderers[0], channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountOperationRight")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveNoRight), nil), FnGetAccountOperationRight, channelName, chaincodeName, roleName, operationName, user.AddressBase58Check)

		By("checking getAccountAllRights")
		client.Query(network, peer, cmn.ChannelAcl, cmn.ChannelAcl, fabricnetwork.CheckResult(aclcmn.CheckGetAccountAllRights(nil, user), nil), FnGetAccountAllRights, user.AddressBase58Check)
	})
})
