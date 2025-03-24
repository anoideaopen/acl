package key_types

import (
	"slices"

	aclcmn "github.com/anoideaopen/acl/tests/integration/cmn"
	aclclient "github.com/anoideaopen/acl/tests/integration/cmn/client"
	"github.com/anoideaopen/foundation/mocks"
	pbfound "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/hyperledger/fabric/integration"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Functions names
const (
	FnEmit      = "emit"
	FnBalanceOf = "balanceOf"
	FnCheckKeys = "checkKeys"

	emitAmount = "1000"

	usersPolicy = 3
)

var _ = Describe("ACL key types tests", func() {
	var ts *aclclient.ACLTestSuite

	Describe("GOST key type tests", func() {
		BeforeEach(func() {
			ts = aclclient.NewTestSuite(components, client.WithAdminKeyType(pbfound.KeyType_gost))
		})
		AfterEach(func() {
			ts.ShutdownNetwork()
		})

		var (
			channels = []string{cmn.ChannelACL, cmn.ChannelFiat}
			user     *mocks.UserFoundation
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
			ts.InitNetwork(channels, integration.GossipBasePort)
			ts.DeployChaincodes()
		})
		BeforeEach(func() {
			By("start robot")
			ts.StartRobot()
		})
		AfterEach(func() {
			By("stop robot")
			ts.StopRobot()
		})

		It("Emit transfer test", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_gost)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			By("emit tokens")
			ts.TxInvokeWithSign(
				cmn.ChannelFiat,
				cmn.ChannelFiat,
				ts.Admin(),
				FnEmit,
				"",
				client.NewNonceByTime().Get(),
				user.AddressBase58Check,
				emitAmount,
			).CheckErrorIsNil()

			By("emit check")
			ts.Query(cmn.ChannelFiat, cmn.ChannelFiat, FnBalanceOf, user.AddressBase58Check).
				CheckBalance(emitAmount)
		})

		It("Setting KYC", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_gost)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			ts.SetKYC(user, "newKychash", ts.Admin())
		})

		It("Change public key with hex encoded key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating users")
			oldUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding old user to ACL")
			ts.AddUser(oldUser)

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("changing user public key")
			ts.ChangePublicKey(
				oldUser,
				newUser.PublicKeyBase58,
				"0",
				"0",
				ts.Admin(),
			)

			By("checking result")
			ts.Query(cmn.ChannelACL, cmn.ChannelACL, FnCheckKeys, newUser.PublicKeyBase58).
				CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser))
		})

		It("Change public key with base58 signature test", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating users")
			oldUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding old user to ACL")
			ts.AddUser(oldUser)

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("changing user public key")
			ts.ChangePublicKeyBase58signed(
				oldUser,
				"0",
				cmn.ChannelACL,
				cmn.ChannelACL,
				newUser.PublicKeyBase58,
				"reason",
				"0",
				ts.Admin(),
			)

			By("checking result")
			ts.Query(cmn.ChannelACL, cmn.ChannelACL, FnCheckKeys, newUser.PublicKeyBase58).
				CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser))
		})

		It("Change multisigned user public key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating multisigned user")
			multisignedUser, err := mocks.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
			Expect(err).NotTo(HaveOccurred())

			By("adding users to ACL")
			for _, user := range multisignedUser.Users {
				ts.AddUser(user)
			}

			By("adding multisigned user")
			ts.AddUserMultisigned(multisignedUser)

			By("creating new user for multisigned")
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("replacing old user to new in multisigned Users collection")
			oldUser := multisignedUser.Users[0]
			multisignedUser.Users = slices.Replace(multisignedUser.Users, 0, 1, newUser)

			By("changing multisigned user public key")
			ts.ChangeMultisigPublicKey(
				multisignedUser,
				oldUser.PublicKeyBase58,
				newUser.PublicKeyBase58,
				"reason",
				"0",
				ts.Admin(),
			)

			// ToDo add check for getting the old address providing the new key
		})

		It("Adding additional key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_gost)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			By("creating new user for additional key")
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_gost)
			Expect(err).NotTo(HaveOccurred())

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("adding additional key")
			ts.AddAdditionalKey(user, newUser.PublicKeyBase58, []string{"tag1, tag2, tag3"}, ts.Admin())

			By("removing additional key")
			ts.RemoveAdditionalKey(user, newUser.PublicKeyBase58, ts.Admin())
		})
	})

	Describe("ETH key type tests", func() {
		BeforeEach(func() {
			ts = aclclient.NewTestSuite(components, client.WithAdminKeyType(pbfound.KeyType_secp256k1))
		})
		AfterEach(func() {
			ts.ShutdownNetwork()
		})

		var (
			channels = []string{cmn.ChannelACL, cmn.ChannelFiat}
			user     *mocks.UserFoundation
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
			ts.InitNetwork(channels, integration.GossipBasePort)
			ts.DeployChaincodes()
		})
		BeforeEach(func() {
			By("start robot")
			ts.StartRobot()
		})
		AfterEach(func() {
			By("stop robot")
			ts.StopRobot()
		})

		It("Emit transfer test", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_secp256k1)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			By("emit tokens")
			ts.TxInvokeWithSign(
				cmn.ChannelFiat,
				cmn.ChannelFiat,
				ts.Admin(),
				FnEmit,
				"",
				client.NewNonceByTime().Get(),
				user.AddressBase58Check,
				emitAmount,
			).CheckErrorIsNil()

			By("emit check")
			ts.Query(cmn.ChannelFiat, cmn.ChannelFiat, FnBalanceOf, user.AddressBase58Check).
				CheckBalance(emitAmount)
		})

		It("Setting KYC", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_gost)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			ts.SetKYC(user, "newKychash", ts.Admin())
		})

		It("Change public key with hex encoded key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating users")
			oldUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding old user to ACL")
			ts.AddUser(oldUser)

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("changing user public key")
			ts.ChangePublicKey(
				oldUser,
				newUser.PublicKeyBase58,
				"0",
				"0",
				ts.Admin(),
			)

			By("checking result")
			ts.Query(cmn.ChannelACL, cmn.ChannelACL, FnCheckKeys, newUser.PublicKeyBase58).
				CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser))
		})

		It("Change public key with base58 signature test", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating users")
			oldUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding old user to ACL")
			ts.AddUser(oldUser)

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("changing user public key")
			ts.ChangePublicKeyBase58signed(
				oldUser,
				"0",
				cmn.ChannelACL,
				cmn.ChannelACL,
				newUser.PublicKeyBase58,
				"reason",
				"0",
				ts.Admin(),
			)

			By("checking result")
			ts.Query(cmn.ChannelACL, cmn.ChannelACL, FnCheckKeys, newUser.PublicKeyBase58).
				CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser))
		})

		It("Change multisigned user public key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating multisigned user")
			multisignedUser, err := mocks.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
			Expect(err).NotTo(HaveOccurred())

			By("adding users to ACL")
			for _, user := range multisignedUser.Users {
				ts.AddUser(user)
			}

			By("adding multisigned user")
			ts.AddUserMultisigned(multisignedUser)

			By("creating new user for multisigned")
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("replacing old user to new in multisigned Users collection")
			oldUser := multisignedUser.Users[0]
			multisignedUser.Users = slices.Replace(multisignedUser.Users, 0, 1, newUser)

			By("changing multisigned user public key")
			ts.ChangeMultisigPublicKey(
				multisignedUser,
				oldUser.PublicKeyBase58,
				newUser.PublicKeyBase58,
				"reason",
				"0",
				ts.Admin(),
			)

			// ToDo add check for getting the old address providing the new key
		})

		It("Adding additional key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_secp256k1)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			By("creating new user for additional key")
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_secp256k1)
			Expect(err).NotTo(HaveOccurred())

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("adding additional key")
			ts.AddAdditionalKey(user, newUser.PublicKeyBase58, []string{"tag1, tag2, tag3"}, ts.Admin())

			By("removing additional key")
			ts.RemoveAdditionalKey(user, newUser.PublicKeyBase58, ts.Admin())
		})
	})

	Describe("ED25519 key type tests", func() {
		BeforeEach(func() {
			ts = aclclient.NewTestSuite(components, client.WithAdminKeyType(pbfound.KeyType_ed25519))
		})
		AfterEach(func() {
			ts.ShutdownNetwork()
		})

		var (
			channels = []string{cmn.ChannelACL, cmn.ChannelFiat}
			user     *mocks.UserFoundation
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
			ts.InitNetwork(channels, integration.GossipBasePort)
			ts.DeployChaincodes()
		})
		BeforeEach(func() {
			By("start robot")
			ts.StartRobot()
		})
		AfterEach(func() {
			By("stop robot")
			ts.StopRobot()
		})

		It("Emit transfer test", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			By("emit tokens")
			ts.TxInvokeWithSign(
				cmn.ChannelFiat,
				cmn.ChannelFiat,
				ts.Admin(),
				FnEmit,
				"",
				client.NewNonceByTime().Get(),
				user.AddressBase58Check,
				emitAmount,
			).CheckErrorIsNil()

			By("emit check")
			ts.Query(cmn.ChannelFiat, cmn.ChannelFiat, FnBalanceOf, user.AddressBase58Check).
				CheckBalance(emitAmount)
		})

		It("Setting KYC", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_gost)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			ts.SetKYC(user, "newKychash", ts.Admin())
		})

		It("Change public key with hex encoded key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating users")
			oldUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding old user to ACL")
			ts.AddUser(oldUser)

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("changing user public key")
			ts.ChangePublicKey(
				oldUser,
				newUser.PublicKeyBase58,
				"0",
				"0",
				ts.Admin(),
			)

			By("checking result")
			ts.Query(cmn.ChannelACL, cmn.ChannelACL, FnCheckKeys, newUser.PublicKeyBase58).
				CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser))
		})

		It("Change public key with base58 signature test", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating users")
			oldUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding old user to ACL")
			ts.AddUser(oldUser)

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("changing user public key")
			ts.ChangePublicKeyBase58signed(
				oldUser,
				"0",
				cmn.ChannelACL,
				cmn.ChannelACL,
				newUser.PublicKeyBase58,
				"reason",
				"0",
				ts.Admin(),
			)

			By("checking result")
			ts.Query(cmn.ChannelACL, cmn.ChannelACL, FnCheckKeys, newUser.PublicKeyBase58).
				CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser))
		})

		It("Change multisigned user public key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("creating multisigned user")
			multisignedUser, err := mocks.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
			Expect(err).NotTo(HaveOccurred())

			By("adding users to ACL")
			for _, user := range multisignedUser.Users {
				ts.AddUser(user)
			}

			By("adding multisigned user")
			ts.AddUserMultisigned(multisignedUser)

			By("creating new user for multisigned")
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("replacing old user to new in multisigned Users collection")
			oldUser := multisignedUser.Users[0]
			multisignedUser.Users = slices.Replace(multisignedUser.Users, 0, 1, newUser)

			By("changing multisigned user public key")
			ts.ChangeMultisigPublicKey(
				multisignedUser,
				oldUser.PublicKeyBase58,
				newUser.PublicKeyBase58,
				"reason",
				"0",
				ts.Admin(),
			)

			// ToDo add check for getting the old address providing the new key
		})

		It("Adding additional key", func() {
			By("add admin to acl")
			ts.AddAdminToACL()

			By("add user to acl")
			var err error
			user, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			ts.AddUser(user)

			By("creating new user for additional key")
			newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
			Expect(err).NotTo(HaveOccurred())

			By("adding new user to ACL")
			ts.AddUser(newUser)

			By("adding additional key")
			ts.AddAdditionalKey(user, newUser.PublicKeyBase58, []string{"tag1, tag2, tag3"}, ts.Admin())

			By("removing additional key")
			ts.RemoveAdditionalKey(user, newUser.PublicKeyBase58, ts.Admin())
		})
	})
})
