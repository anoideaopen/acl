package account

import (
	aclcmn "github.com/anoideaopen/acl/tests/integration/cmn"
	aclclient "github.com/anoideaopen/acl/tests/integration/cmn/client"
	pbfound "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/hyperledger/fabric/integration"
	"github.com/hyperledger/fabric/integration/nwo"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Functions names
const (
	FnCheckKeys      = "checkKeys"
	FnGetAccountInfo = "getAccountInfo"
)

var _ = Describe("ACL basic tests", func() {
	var (
		ts client.TestSuite

		network *nwo.Network
		peer    *nwo.Peer
		orderer *nwo.Orderer
	)

	BeforeEach(func() {
		ts = client.NewTestSuite(components)
	})
	AfterEach(func() {
		ts.ShutdownNetwork()
	})

	var (
		channels = []string{cmn.ChannelAcl}
		user     *client.UserFoundation
	)
	BeforeEach(func() {
		By("start redis")
		ts.StartRedis()
	})
	AfterEach(func() {
		By("stop redis")
		ts.StopRedis()
	})
	BeforeEach(func() {
		ts.InitNetwork(channels, integration.DiscoveryBasePort)
		ts.DeployChaincodes()

		network = ts.Network()
		peer = ts.Peer()
		orderer = network.Orderers[0]
	})

	It("Get Account Info test", func() {
		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		etalonAccountInfo := &pbfound.AccountInfo{
			KycHash:     "kycHash2",
			GrayListed:  true,
			BlackListed: true,
		}

		By("setting account info")
		aclclient.SetAccountInfo(
			network,
			peer,
			orderer,
			user,
			etalonAccountInfo.GetKycHash(),
			etalonAccountInfo.GetGrayListed(),
			etalonAccountInfo.GetBlackListed(),
		)

		By("getting account info")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnGetAccountInfo, user.AddressBase58Check).
			CheckResponseWithFunc(aclcmn.CheckAccountInfo(etalonAccountInfo))
	})

	It("Set KYC test", func() {
		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		etalonAccountInfo := &pbfound.AccountInfo{
			KycHash:     "kycHash2",
			GrayListed:  false,
			BlackListed: false,
		}

		By("setting account info")
		aclclient.SetKYC(network, peer, orderer, user, etalonAccountInfo.GetKycHash(), ts.Admin())

		By("getting account info with checkKeys function")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(etalonAccountInfo, user))
	})

	It("Set Account Info test", func() {
		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		etalonAccountInfo := &pbfound.AccountInfo{
			KycHash:     "kycHash2",
			GrayListed:  true,
			BlackListed: true,
		}

		By("setting account info")
		aclclient.SetAccountInfo(
			network,
			peer,
			orderer,
			user,
			etalonAccountInfo.GetKycHash(),
			etalonAccountInfo.GetGrayListed(),
			etalonAccountInfo.GetBlackListed(),
		)

		By("getting account info")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnGetAccountInfo, user.AddressBase58Check).
			CheckResponseWithFunc(aclcmn.CheckAccountInfo(etalonAccountInfo))

		By("getting account info with checkKeys function")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(etalonAccountInfo, user))

		etalonAccountInfo.GrayListed = false

		By("setting account info")
		aclclient.SetAccountInfo(
			network,
			peer,
			orderer,
			user,
			etalonAccountInfo.GetKycHash(),
			etalonAccountInfo.GetGrayListed(),
			etalonAccountInfo.GetBlackListed(),
		)

		By("getting account info")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnGetAccountInfo, user.AddressBase58Check).
			CheckResponseWithFunc(aclcmn.CheckAccountInfo(etalonAccountInfo))

		By("getting account info with checkKeys function")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(etalonAccountInfo, user))

		etalonAccountInfo.BlackListed = false

		By("setting account info")
		aclclient.SetAccountInfo(
			network,
			peer,
			orderer,
			user,
			etalonAccountInfo.GetKycHash(),
			etalonAccountInfo.GetGrayListed(),
			etalonAccountInfo.GetBlackListed(),
		)

		By("getting account info")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnGetAccountInfo, user.AddressBase58Check).
			CheckResponseWithFunc(aclcmn.CheckAccountInfo(etalonAccountInfo))

		By("getting account info with checkKeys function")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(etalonAccountInfo, user))

		etalonAccountInfo.GrayListed = true

		By("setting account info")
		aclclient.SetAccountInfo(
			network,
			peer,
			orderer,
			user,
			etalonAccountInfo.GetKycHash(),
			etalonAccountInfo.GetGrayListed(),
			etalonAccountInfo.GetBlackListed(),
		)

		By("getting account info")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnGetAccountInfo, user.AddressBase58Check).
			CheckResponseWithFunc(aclcmn.CheckAccountInfo(etalonAccountInfo))

		By("getting account info with checkKeys function")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(etalonAccountInfo, user))
	})
})
