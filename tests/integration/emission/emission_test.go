package emission

import (
	"slices"

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

	usersPolicy = 3
	emitAmount  = "1000"
)

var _ = Describe("ACL emission tests", func() {
	var ts client.TestSuite

	BeforeEach(func() {
		ts = client.NewTestSuite(components)
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
		ts.InitNetwork(channels, integration.SmartBFTBasePort)
		ts.DeployChaincodesByName([]string{cmn.ChannelACL})
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

		By("deploying fiat channel")
		ts.DeployFiat(
			ts.Admin().AddressBase58Check,
			ts.FeeSetter().AddressBase58Check,
			ts.FeeAddressSetter().AddressBase58Check,
		)

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

	It("Multisigned emit transfer test", func() {
		By("add admin to acl")
		ts.AddAdminToACL()

		By("creating multisigned user")
		multisigUser, err := mocks.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
		Expect(err).NotTo(HaveOccurred())

		By("adding users to ACL")
		for _, user := range multisigUser.Users {
			ts.AddUser(user)
		}

		By("adding multisign")
		ts.AddUserMultisigned(multisigUser)

		By("deploying fiat channel")
		ts.DeployFiat(
			multisigUser.AddressBase58Check,
			ts.FeeSetter().AddressBase58Check,
			ts.FeeAddressSetter().AddressBase58Check,
		)

		By("add user to acl")
		user, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		By("emit tokens")
		ts.TxInvokeWithMultisign(
			cmn.ChannelFiat,
			cmn.ChannelFiat,
			multisigUser,
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

	It("Multisig change pub key test", func() {
		By("add admin to acl")
		ts.AddAdminToACL()

		By("creating multisigned user")
		multisigUser, err := mocks.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
		Expect(err).NotTo(HaveOccurred())

		By("adding users to ACL")
		for _, user := range multisigUser.Users {
			ts.AddUser(user)
		}

		By("adding multisign")
		ts.AddUserMultisigned(multisigUser)

		By("deploying fiat channel")
		ts.DeployFiat(
			multisigUser.AddressBase58Check,
			ts.FeeSetter().AddressBase58Check,
			ts.FeeAddressSetter().AddressBase58Check,
		)

		By("creating new user for multisig")
		newUser, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		By("adding new user to ACL")
		ts.AddUser(newUser)

		By("replacing old user to new in multisigned Users collection")
		oldUser := multisigUser.Users[0]
		multisigUser.Users = slices.Replace(multisigUser.Users, 0, 1, newUser)

		By("changing multisigned user public key")
		ts.ChangeMultisigPublicKey(
			multisigUser,
			oldUser.PublicKeyBase58,
			newUser.PublicKeyBase58,
			"reason",
			"0",
			ts.Admin(),
		)

		By("add user to acl")
		user, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		By("emit tokens")
		ts.TxInvokeWithMultisign(
			cmn.ChannelFiat,
			cmn.ChannelFiat,
			multisigUser,
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
})
