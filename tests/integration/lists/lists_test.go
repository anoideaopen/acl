package lists

import (
	aclcmn "github.com/anoideaopen/acl/tests/integration/cmn"
	pbfound "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/hyperledger/fabric/integration"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Functions names
const (
	FnCheckKeys = "checkKeys"
)

var _ = Describe("ACL lists tests", func() {
	var (
		ts client.TestSuite
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
		ts.InitNetwork(channels, integration.LedgerPort)
		ts.DeployChaincodes()
	})

	It("Black & Gray lists test", func() {
		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		By("adding user to GrayList")
		ts.AddToGrayList(user)

		By("sending query & checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountGraylisted, user))

		By("adding user to BlackList")
		ts.AddToBlackList(user)

		By("sending query & checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountBothLists, user))
	})

	It("Del from list test", func() {
		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		By("adding user to GrayList")
		ts.AddToGrayList(user)

		By("sending query & checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountGraylisted, user))

		By("adding user to BlackList")
		ts.AddToBlackList(user)

		By("sending query & checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountBothLists, user))

		By("deleting from GrayList")
		ts.DelFromGrayList(user)

		By("sending query & checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountBlacklisted, user))

		By("deleting from BlackList")
		ts.DelFromBlackList(user)

		By("sending query & checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, user))
	})
})
