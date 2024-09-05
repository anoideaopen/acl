package rights

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
	FnGetAccountOperationRight = "getAccountOperationRight"
	FnGetAccountAllRights      = "getAccountAllRights"
	FnGetOperationAllRights    = "getOperationAllRights"
)

var _ = Describe("ACL integration rights tests", func() {
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
		ts.InitNetwork(channels, integration.RaftBasePort)
		ts.DeployChaincodes()
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

		ts.AddUser(user)

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
		ts.AddRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountAllRights")
		ts.Query(cmn.ChannelAcl, cmn.ChannelAcl, FnGetAccountAllRights, user.AddressBase58Check).
			CheckResponseWithFunc(aclcmn.CheckGetAccountAllRights(etalonRights, user))

		By("checking getAccountOperationRight")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountOperationRight,
			channelName,
			chaincodeName,
			roleName,
			operationName,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveRight))

		By("checking getOperationAllRights")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetOperationAllRights,
			channelName,
			chaincodeName,
			roleName,
			operationName,
		).CheckResponseWithFunc(aclcmn.CheckGetOperationAllRights(etalonOperationHaveRights, user))

		By("removing right")
		ts.RemoveRights(channelName, chaincodeName, roleName, operationName, user)
		etalonRights = nil
		etalonOperationHaveRights.Rights = nil

		By("checking getAccountOperationRight")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountOperationRight,
			channelName,
			chaincodeName,
			roleName,
			operationName,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveNoRight))

		By("checking getOperationAllRights")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetOperationAllRights,
			channelName,
			chaincodeName,
			roleName,
			operationName,
		).CheckResponseWithFunc(aclcmn.CheckGetOperationAllRights(etalonOperationHaveRights, user))

		By("checking getAccountAllRights")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountAllRights,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountAllRights(etalonRights, user))
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

		ts.AddUser(user)

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
		ts.AddRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking result")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountAllRights,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountAllRights(etalonRights, user))

		By("removing right")
		ts.RemoveRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking result")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountAllRights,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountAllRights(nil, user))
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

		ts.AddUser(user)

		By("adding right")
		ts.AddRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountOperationRight")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountOperationRight,
			channelName,
			chaincodeName,
			roleName,
			operationName,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveRight))

		By("removing right")
		ts.RemoveRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountOperationRight")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountOperationRight,
			channelName,
			chaincodeName,
			roleName,
			operationName,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveNoRight))
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

		ts.AddUser(user)

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
		ts.AddRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking getOperationAllRights")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetOperationAllRights,
			channelName,
			chaincodeName,
			roleName,
			operationName,
		).CheckResponseWithFunc(aclcmn.CheckGetOperationAllRights(etalonOperationHaveRights, user))

		By("removing right")
		ts.RemoveRights(channelName, chaincodeName, roleName, operationName, user)
		etalonOperationHaveRights.Rights = nil

		By("checking getOperationAllRights")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetOperationAllRights,
			channelName,
			chaincodeName,
			roleName,
			operationName,
		).CheckResponseWithFunc(aclcmn.CheckGetOperationAllRights(etalonOperationHaveRights, user))
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

		ts.AddUser(user)

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
		ts.AddRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountAllRights")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountAllRights,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountAllRights(etalonRights, user))

		By("checking getAccountOperationRight")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountOperationRight,
			channelName,
			chaincodeName,
			roleName,
			operationName,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveRight))

		By("removing right")
		ts.RemoveRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountOperationRight")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountOperationRight,
			channelName,
			chaincodeName,
			roleName,
			operationName,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveNoRight))

		By("checking getAccountAllRights")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountAllRights,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountAllRights(nil, user))

		By("removing rights again")
		ts.RemoveRights(channelName, chaincodeName, roleName, operationName, user)

		By("checking getAccountOperationRight")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountOperationRight,
			channelName,
			chaincodeName,
			roleName,
			operationName,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountOperationRight(aclcmn.TestHaveNoRight))

		By("checking getAccountAllRights")
		ts.Query(
			cmn.ChannelAcl,
			cmn.ChannelAcl,
			FnGetAccountAllRights,
			user.AddressBase58Check,
		).CheckResponseWithFunc(aclcmn.CheckGetAccountAllRights(nil, user))
	})
})
