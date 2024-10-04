package basic

import (
	"slices"

	aclcmn "github.com/anoideaopen/acl/tests/integration/cmn"
	aclclient "github.com/anoideaopen/acl/tests/integration/cmn/client"
	pbfound "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/hyperledger/fabric/integration"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Functions names
const (
	FnCheckKeys                  = "checkKeys"
	FnCheckAddress               = "checkAddress"
	FnGetAddresses               = "getAddresses"
	FnGetAddressRightForNominee  = "getAddressRightForNominee"
	FnGetAddressesListForNominee = "getAddressesListForNominee"

	usersPolicy = 3
)

var _ = Describe("ACL basic tests", func() {
	var (
		ts *aclclient.AclTestSuite
	)

	BeforeEach(func() {
		ts = aclclient.NewTestSuite(components)
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
		ts.InitNetwork(channels, integration.DevModePort)
		ts.DeployChaincodes()
	})

	It("Add user test & check keys test", func() {
		By("add user to acl")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		By("checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, user))
	})

	It("Add multisigned user test", func() {
		By("creating multisgined user")
		user1, err := client.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
		Expect(err).NotTo(HaveOccurred())

		By("adding users to ACL")
		for _, user := range user1.Users {
			ts.AddUser(user)
		}

		By("adding multisigned user")
		ts.AddUserMultisigned(user1)

		// ToDo add check multisigned user
	})

	It("Change public key with hex encoded key", func() {
		By("add admin to acl")
		ts.AddAdminToACL()

		By("creating users")
		oldUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		newUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
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
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, newUser.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser))
	})

	It("Change public key with base58 signature test", func() {
		By("add admin to acl")
		ts.AddAdminToACL()

		By("creating users")
		oldUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		newUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		By("adding old user to ACL")
		ts.AddUser(oldUser)

		By("adding new user to ACL")
		ts.AddUser(newUser)

		By("changing user public key")
		ts.ChangePublicKeyBase58signed(
			oldUser,
			"0",
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			newUser.PublicKeyBase58,
			"reason",
			"0",
			ts.Admin(),
		)

		By("checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, newUser.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, oldUser))
	})

	It("Change multisigned user public key", func() {
		By("add admin to acl")
		ts.AddAdminToACL()

		By("creating multisigned user")
		multisignedUser, err := client.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
		Expect(err).NotTo(HaveOccurred())

		By("adding users to ACL")
		for _, user := range multisignedUser.Users {
			ts.AddUser(user)
		}

		By("adding multisigned user")
		ts.AddUserMultisigned(multisignedUser)

		By("creating new user for multisigned")
		newUser, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
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

	It("Check address test", func() {
		By("add admin to acl")
		ts.AddAdminToACL()

		By("creating user")
		var err error
		user, err = client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		By("adding old user to ACL")
		ts.AddUser(user)

		By("checking address")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckAddress, user.AddressBase58Check).
			CheckResponseWithFunc(aclcmn.CheckAddress(user))

		By("add user to gray list")
		ts.AddToGrayList(user)

		By("checking address")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckAddress, user.AddressBase58Check).
			CheckErrorEquals("address " + user.AddressBase58Check + " is graylisted")
	})

	It("Get Addresses test", func() {
		By("adding users to acl")
		user1, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		user2, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		user3, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user1)
		ts.AddUser(user2)
		ts.AddUser(user3)

		By("checking users")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnGetAddresses, "100", "").
			CheckResponseWithFunc(aclcmn.CheckAddresses(user1, user2, user3))
	})

	It("nominee methods test", func() {
		By("adding users to acl")
		ts.AddAdminToACL()

		nominee, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		principal, err := client.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)
		ts.AddUser(nominee)
		ts.AddUser(principal)

		By("adding address for nominee")
		ts.AddAddressForNominee(cmn.ChannelAcl, cmn.ChannelAcl, nominee, principal)

		By("checking if address added")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAddressesListForNominee,
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			nominee.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAddressesListForNominee([]string{principal.AddressBase58Check}))

		By("[negative] checking right for another user")
		By("checking address right")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAddressRightForNominee,
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			nominee.AddressBase58Check,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckAddressRightForNominee(false))

		By("adding same address again")
		ts.AddAddressForNominee(cmn.ChannelAcl, cmn.ChannelAcl, nominee, principal)

		By("checking if address was not added")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAddressesListForNominee,
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			nominee.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAddressesListForNominee([]string{principal.AddressBase58Check}))

		By("checking address right")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAddressRightForNominee,
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			nominee.AddressBase58Check,
			principal.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckAddressRightForNominee(true))

		By("Removing right from nominee")
		ts.RemoveAddressFromNominee(cmn.ChannelAcl, cmn.ChannelAcl, nominee, principal)

		By("checking address right")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAddressRightForNominee,
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			nominee.AddressBase58Check,
			principal.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckAddressRightForNominee(false))
	})
})
