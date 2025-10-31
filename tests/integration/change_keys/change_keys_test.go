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
	txComment   = "comment"
	txReason    = "reason"
	txReasonID  = "1"
	txRequestID = "1"
)

var _ = Describe("ACL change public key tests", func() {
	var (
		channels     = []string{cmn.ChannelACL, cmn.ChannelFiat, cmn.ChannelIndustrial}
		ts           *aclclient.ACLTestSuite
		user1, user2 *mocks.UserFoundation
	)

	BeforeEach(func() {
		ts = aclclient.NewTestSuite(components)
	})
	AfterEach(func() {
		ts.ShutdownNetwork()
	})

	BeforeEach(func() {
		ts.InitNetwork(channels, integration.E2EBasePort)
		ts.DeployChaincodes()
	})

	It("Change public key test", func() {
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

		By("initialize industrial")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnIndustrialInitialize)

		By("transfer initial tokens")
		var (
			tokenGroup     = "202009"
			initialBalance = big.NewInt(10000000000000)
		)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, ts.Admin().AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnTransferIndustrial,
			user1.AddressBase58Check, tokenGroup, initialBalance.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user1.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())

		By("transfer tokens to another user with the old key")
		var transferAmount = initialBalance.Div(initialBalance, big.NewInt(2))
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, user1, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, transferAmount.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, transferAmount.String())

		By("change public key")
		var newKey *mocks.UserFoundation
		newKey, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.ChangePublicKey(user1, newKey.PublicKeyBase58, txReason, txReasonID, ts.Admin())

		By("transfer tokens to another user with the new key")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, user1, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, transferAmount.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
	})

	It("Change public key test with base58-encoded signatures", func() {
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

		By("initialize industrial")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnIndustrialInitialize)

		By("transfer initial tokens")
		var (
			tokenGroup     = "202009"
			initialBalance = big.NewInt(10000000000000)
		)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, ts.Admin().AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnTransferIndustrial,
			user1.AddressBase58Check, tokenGroup, initialBalance.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user1.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())

		By("transfer tokens to another user with the old key")
		var transferAmount = initialBalance.Div(initialBalance, big.NewInt(2))
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, user1, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, transferAmount.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, transferAmount.String())

		By("change public key")
		var newKey *mocks.UserFoundation
		newKey, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.ChangePublicKeyBase58signed(user1, txRequestID, cmn.ChannelACL, cmn.ChannelACL,
			newKey.PublicKeyBase58, txReason, txReasonID, ts.Admin())

		By("transfer tokens to another user with the new key")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, user1, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, transferAmount.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
	})

	It("Change public key with key type test", func() {
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

		By("initialize industrial")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnIndustrialInitialize)

		By("transfer initial tokens")
		var (
			tokenGroup     = "202009"
			initialBalance = big.NewInt(10000000000000)
		)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, ts.Admin().AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnTransferIndustrial,
			user1.AddressBase58Check, tokenGroup, initialBalance.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user1.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())

		By("transfer tokens to another user with the old key")
		var transferAmount = initialBalance.Div(initialBalance, big.NewInt(2))
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, user1, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, transferAmount.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, transferAmount.String())

		By("change public key and its type")
		var newKey *mocks.UserFoundation
		newKey, err = mocks.NewUserFoundation(pbfound.KeyType_secp256k1)
		Expect(err).NotTo(HaveOccurred())

		ts.ChangePublicKeyWithType(user1, newKey.PublicKeyBase58, pbfound.KeyType_secp256k1, txReason, txReasonID, ts.Admin())

		By("transfer tokens to another user with the new key")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, user1, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, transferAmount.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
	})

	It("Change public key with key type and base58-encoded signatures test", func() {
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

		By("initialize industrial")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnIndustrialInitialize)

		By("transfer initial tokens")
		var (
			tokenGroup     = "202009"
			initialBalance = big.NewInt(10000000000000)
		)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, ts.Admin().AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, ts.Admin(), FnTransferIndustrial,
			user1.AddressBase58Check, tokenGroup, initialBalance.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user1.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())

		By("transfer tokens to another user with the old key")
		var transferAmount = initialBalance.Div(initialBalance, big.NewInt(2))
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, user1, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, transferAmount.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, transferAmount.String())

		By("change public key and its type")
		var newKey *mocks.UserFoundation
		newKey, err = mocks.NewUserFoundation(pbfound.KeyType_secp256k1)
		Expect(err).NotTo(HaveOccurred())

		ts.ChangePublicKeyWithTypeBase58signed(user1, txRequestID, cmn.ChannelACL, cmn.ChannelACL,
			newKey.PublicKeyBase58, pbfound.KeyType_secp256k1, txReason, txReasonID, ts.Admin())

		By("transfer tokens to another user with the new key")
		ts.ExecuteTaskWithSign(cmn.ChannelIndustrial, cmn.ChannelIndustrial, user1, FnTransferIndustrial,
			user2.AddressBase58Check, tokenGroup, transferAmount.String(), txComment)
		ts.Query(cmn.ChannelIndustrial, cmn.ChannelIndustrial, FnIndustrialBalanceOf, user2.AddressBase58Check).
			CheckIndustrialBalance(tokenGroup, initialBalance.String())
	})
})
