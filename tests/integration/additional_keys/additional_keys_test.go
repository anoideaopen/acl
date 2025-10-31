package change_keys

import (
	aclclient "github.com/anoideaopen/acl/tests/integration/cmn/client"
	"github.com/anoideaopen/foundation/core/types/big"
	"github.com/anoideaopen/foundation/mocks"
	pbfound "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/hyperledger/fabric/integration"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	FnIndustrialInitialize = "initialize"
	FnIndustrialBalanceOf  = "industrialBalanceOf"
	FnTransferIndustrial   = "transferIndustrial"
)

const (
	keyLabel  = "test key"
	txComment = "comment"
)

var _ = Describe("ACL additional keys tests", func() {
	var (
		channels                    = []string{cmn.ChannelACL, cmn.ChannelIndustrial}
		ts                          *aclclient.ACLTestSuite
		user1, user2, additionalKey *mocks.UserFoundation
	)

	var (
		tokenGroup     = "202009"
		initialBalance = big.NewInt(10000000000000)
	)

	BeforeEach(func() {
		ts = aclclient.NewTestSuite(components)
	})
	AfterEach(func() {
		ts.ShutdownNetwork()
	})

	BeforeEach(func() {
		ts.InitNetwork(channels, integration.GatewayBasePort)
		ts.DeployChaincodes()
	})

	It("ed25519 additional key test", func() {
		var err error

		By("add admin to acl")
		ts.AddAdminToACL()

		By("add users to acl")
		user1, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		ts.AddUser(user1)

		user2, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		ts.AddUser(user2)

		additionalKey, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		By("add additional key to acl")
		ts.AddAdditionalKey(user1, additionalKey.PublicKeyBase58, []string{keyLabel}, ts.Admin())

		By("initialize industrial")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnIndustrialInitialize)

		By("transfer initial tokens")
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, ts.Admin().AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnTransferIndustrial,
			user1.AddressBase58Check, tokenGroup, initialBalance.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user1.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())

		By("transfer tokens to another user with the additional key")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, additionalKey, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, initialBalance.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user1.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, big.NewInt(0).String())
	})

	It("secp256k1 additional key test", func() {
		var err error

		By("add admin to acl")
		ts.AddAdminToACL()

		By("add users to acl")
		user1, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		ts.AddUser(user1)

		user2, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		ts.AddUser(user2)

		additionalKey, err = mocks.NewUserFoundation(pbfound.KeyType_secp256k1)
		Expect(err).NotTo(HaveOccurred())

		By("add additional key to acl")
		ts.AddAdditionalKey(user1, additionalKey.PublicKeyBase58, []string{keyLabel}, ts.Admin())

		By("initialize industrial")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnIndustrialInitialize)

		By("transfer initial tokens")
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, ts.Admin().AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnTransferIndustrial,
			user1.AddressBase58Check, tokenGroup, initialBalance.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user1.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())

		By("transfer tokens to another user with the additional key")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, additionalKey, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, initialBalance.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user1.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, big.NewInt(0).String())
	})
})
