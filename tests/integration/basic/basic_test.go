package basic

import (
	aclcmn "github.com/anoideaopen/acl/tests/integration/cmn"
	aclclient "github.com/anoideaopen/acl/tests/integration/cmn/client"
	"github.com/anoideaopen/foundation/mocks"
	pbfound "github.com/anoideaopen/foundation/proto"
	"github.com/anoideaopen/foundation/test/integration/cmn"
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
		ts.InitNetwork(channels, integration.DevModePort)
		ts.DeployChaincodes()
	})

	It("Add user test & check keys test", func() {
		By("add user to acl")
		var err error
		user, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())

		ts.AddUser(user)

		By("checking result")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnCheckKeys, user.PublicKeyBase58).
			CheckResponseWithFunc(aclcmn.CheckKeys(aclcmn.TestAccountNotListed, user))
	})

	It("Add multisigned user test", func() {
		By("creating multisgined user")
		user1, err := mocks.NewUserFoundationMultisigned(pbfound.KeyType_ed25519, usersPolicy)
		Expect(err).NotTo(HaveOccurred())

		By("adding users to ACL")
		for _, user := range user1.Users {
			ts.AddUser(user)
		}

		By("adding multisigned user")
		ts.AddUserMultisigned(user1)

		// ToDo add check multisigned user
	})

	It("Check address test", func() {
		By("add admin to acl")
		ts.AddAdminToACL()

		By("creating user")
		var err error
		user, err = mocks.NewUserFoundation(pbfound.KeyType_ed25519)
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
		user1, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		user2, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		user3, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
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

		nominee, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
		Expect(err).NotTo(HaveOccurred())
		principal, err := mocks.NewUserFoundation(pbfound.KeyType_ed25519)
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
