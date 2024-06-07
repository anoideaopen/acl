package cmn

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	ginkgomon "github.com/tedsuo/ifrit/ginkgomon_v2"
)

const (
	HttpPort nwo.PortName = "HttpPort"
	GrpcPort nwo.PortName = "GrpcPort"
)

// NetworkFoundation holds information about a fabric network.
type NetworkFoundation struct {
	*nwo.Network
	Robot           *Robot
	ChannelTransfer *ChannelTransfer
	Templates       *TemplatesFound
	Channels        []string

	mutex      sync.Locker
	colorIndex uint
}

func New(network *nwo.Network, channels []string) *NetworkFoundation {
	n := &NetworkFoundation{
		Network: network,
		Templates: &TemplatesFound{
			Templates: network.Templates,
		},
		Channels: channels,
		Robot:    &Robot{Ports: nwo.Ports{}},
		ChannelTransfer: &ChannelTransfer{
			HostAddress: "localhost",
			AccessToken: "test",
			Ports:       nwo.Ports{},
			TTL:         "10800s",
		},
		mutex: &sync.Mutex{},
	}
	for _, portName := range RobotPortNames() {
		n.Robot.Ports[portName] = n.ReservePort()
	}

	for _, portName := range ChannelTransferPortNames() {
		n.ChannelTransfer.Ports[portName] = n.ReservePort()
	}

	return n
}

// Robot structure defines Robot service
type Robot struct {
	Ports          nwo.Ports `yaml:"ports,omitempty"`
	RedisAddresses []string  `yaml:"redis_addresses,omitempty"`
}

// ChannelTransfer defines Channel Transfer service
type ChannelTransfer struct {
	HostAddress    string    `yaml:"host_address,omitempty"`
	Ports          nwo.Ports `yaml:"ports,omitempty"`
	RedisAddresses []string  `yaml:"redis_addresses,omitempty"`
	AccessToken    string    `yaml:"access_token,omitempty"`
	TTL            string    `yaml:"ttl,omitempty"`
}

func (n *NetworkFoundation) GenerateConfigTree() {
	n.Network.GenerateConfigTree()
	peer := n.Peer("Org1", "peer0")
	n.GenerateConnection(peer, "User1")
	n.GenerateConnection(peer, "User2")
	n.GenerateRobotConfig("User2")
	n.GenerateChannelTransferConfig("User2")
}

// GenerateConnection creates the `connection.yaml` configuration file
// provided to profile `connection` for client. The path to the generated
// file can be obtained from ConnectionPath.
func (n *NetworkFoundation) GenerateConnection(p *nwo.Peer, u string) {
	config, err := os.Create(n.ConnectionPath(u))
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := config.Close()
		Expect(err).NotTo(HaveOccurred())
	}()

	t, err := template.New("connection").Funcs(template.FuncMap{
		"Peer": func() *nwo.Peer { return p },
		"User": func() string { return u },
	}).Parse(n.Templates.ConnectionTemplate())
	Expect(err).NotTo(HaveOccurred())

	pw := gexec.NewPrefixedWriter(fmt.Sprintf("[%s#connection.yaml] ", u), ginkgo.GinkgoWriter)
	err = t.Execute(io.MultiWriter(config, pw), n)
	Expect(err).NotTo(HaveOccurred())
}

// GenerateRobotConfig creates the `robot.yaml` configuration file
// provided to config for robot. The path to the generated
// file can be obtained from RobotPath.
func (n *NetworkFoundation) GenerateRobotConfig(u string) {
	config, err := os.Create(n.RobotPath())
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := config.Close()
		Expect(err).NotTo(HaveOccurred())
	}()

	t, err := template.New("robot").Funcs(template.FuncMap{
		"User": func() string { return u },
	}).Parse(n.Templates.RobotTemplate())
	Expect(err).NotTo(HaveOccurred())

	pw := gexec.NewPrefixedWriter("[robot.yaml] ", ginkgo.GinkgoWriter)
	err = t.Execute(io.MultiWriter(config, pw), n)
	Expect(err).NotTo(HaveOccurred())
}

// GenerateChannelTransferConfig creates the `robot.yaml` configuration file
// provided to config for Channel Transfer service. The path to the generated
// file can be obtained from ChannelTransferPath.
func (n *NetworkFoundation) GenerateChannelTransferConfig(user string) {
	config, err := os.Create(n.ChannelTransferPath())
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := config.Close()
		Expect(err).NotTo(HaveOccurred())
	}()

	t, err := template.New("channel_transfer").Funcs(template.FuncMap{
		"User": func() string { return user },
	}).Parse(n.Templates.ChannelTransferTemplate())
	Expect(err).NotTo(HaveOccurred())

	pw := gexec.NewPrefixedWriter("[channel_transfer.yaml] ", ginkgo.GinkgoWriter)
	err = t.Execute(io.MultiWriter(config, pw), n)
	Expect(err).NotTo(HaveOccurred())
}

// ConnectionPath returns the path to the generated connection profile file.
func (n *NetworkFoundation) ConnectionPath(user string) string {
	return filepath.Join(n.RootDir, user+"_connection.yaml")
}

// RobotPath returns the path to the generated robot profile file.
func (n *NetworkFoundation) RobotPath() string {
	return filepath.Join(n.RootDir, "robot.yaml")
}

// ChannelTransferPath returns the path to the generated connection profile
func (n *NetworkFoundation) ChannelTransferPath() string {
	return filepath.Join(n.RootDir, "channel_transfer.yaml")
}

// PeerUserKeyFound returns the path to the private key for the specified user in
// the peer organization.
func (n *NetworkFoundation) PeerUserKeyFound(p *nwo.Peer, user string) string {
	org := n.Organization(p.Organization)
	Expect(org).NotTo(BeNil())

	keystore := filepath.Join(
		n.PeerUserMSPDir(p, user),
		"keystore",
	)

	// file names are the SKI and non-deterministic
	keys, err := os.ReadDir(keystore)
	if err != nil {
		return filepath.Join(keystore, "priv_sk")
	}

	Expect(keys).To(HaveLen(1))

	return filepath.Join(keystore, keys[0].Name())
}

// RobotPortNames  returns the list of ports that need to be reserved for a robot.
func RobotPortNames() []nwo.PortName {
	return []nwo.PortName{nwo.ListenPort}
}

// ChannelTransferPortNames returns the list of ports that need to be reserved for the Channel Transfer service
func ChannelTransferPortNames() []nwo.PortName {
	return []nwo.PortName{nwo.HostPort, GrpcPort, HttpPort}
}

// ChannelTransferPort returns the named port reserved for the Channel Transfer instance
func (n *NetworkFoundation) ChannelTransferPort(portName nwo.PortName) string {
	ports := n.ChannelTransfer.Ports
	Expect(ports).NotTo(BeNil())
	return fmt.Sprintf("%d", ports[portName])
}

// channelTransferHost returns Channel Transfer host
func (n *NetworkFoundation) channelTransferHost() string {
	address := n.ChannelTransfer.HostAddress
	Expect(address).NotTo(BeNil())
	return address
}

// ChannelTransferHostAddress returns channel transfer host & port as a string
func (n *NetworkFoundation) ChannelTransferHostAddress() string {
	host := n.channelTransferHost()
	port := n.ChannelTransferPort(nwo.HostPort)
	return net.JoinHostPort(host, port)
}

// ChannelTransferGRPCAddress returns channel transfer GRPC host & port as a string
func (n *NetworkFoundation) ChannelTransferGRPCAddress() string {
	host := n.channelTransferHost()
	port := n.ChannelTransferPort(GrpcPort)
	return net.JoinHostPort(host, port)
}

// ChannelTransferHTTPAddress returns channel transfer HTTP host & port as a string
func (n *NetworkFoundation) ChannelTransferHTTPAddress() string {
	host := n.channelTransferHost()
	port := n.ChannelTransferPort(HttpPort)
	return net.JoinHostPort(host, port)
}

// ChannelTransferAccessToken returns Channel Transfer access token
func (n *NetworkFoundation) ChannelTransferAccessToken() string {
	token := n.ChannelTransfer.AccessToken
	Expect(token).NotTo(BeNil())
	return token
}

// ChannelTransferTTL returns Channel Transfer TTL value
func (n *NetworkFoundation) ChannelTransferTTL() string {
	ttl := n.ChannelTransfer.TTL
	Expect(ttl).NotTo(BeNil())
	return ttl
}

// RobotPort returns the named port reserved for the Robot instance.
func (n *NetworkFoundation) RobotPort(portName nwo.PortName) uint16 {
	peerPorts := n.Robot.Ports
	Expect(peerPorts).NotTo(BeNil())
	return peerPorts[portName]
}

// RobotRunner returns an ifrit.Runner for the specified robot. The runner can be
// used to start and manage a robot process.
func (n *NetworkFoundation) RobotRunner(env ...string) *ginkgomon.Runner {
	cmd := exec.Command(n.Components.Build(RobotModulePath()), "-c", n.RobotPath())
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, env...)

	return ginkgomon.New(ginkgomon.Config{
		AnsiColorCode:     n.nextColor(),
		Name:              "robot",
		Command:           cmd,
		StartCheck:        `Robot started, time -`,
		StartCheckTimeout: 15 * time.Second,
	})
}

// ChannelTransferRunner returns an ifrit.Runner for the specified channel_transfer service. The runner can be
// used to start and manage the channel_transfer process.
func (n *NetworkFoundation) ChannelTransferRunner(env ...string) *ginkgomon.Runner {
	cmd := exec.Command(n.Components.Build(ChannelTransferModulePath()), "-c", n.ChannelTransferPath())
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, env...)

	return ginkgomon.New(ginkgomon.Config{
		AnsiColorCode:     n.nextColor(),
		Name:              "channel_transfer",
		Command:           cmd,
		StartCheck:        `Channel transfer started, time -`,
		StartCheckTimeout: 15 * time.Second,
	})
}

func (n *NetworkFoundation) nextColor() string {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	cInd := n.colorIndex + 7
	color := cInd%14 + 31
	if color > 37 {
		color = color + 90 - 37
	}

	n.colorIndex++
	return fmt.Sprintf("%dm", color)
}

func RobotModulePath() string {
	return "github.com/anoideaopen/robot"
}

func ChannelTransferModulePath() string {
	return "github.com/anoideaopen/channel-transfer"
}

func AclModulePath() string {
	return "github.com/anoideaopen/acl"
}

func CcModulePath() string {
	return "github.com/anoideaopen/foundation/test/chaincode/cc"
}

func FiatModulePath() string {
	return "github.com/anoideaopen/foundation/test/chaincode/fiat"
}

func IndustrialModulePath() string {
	return "github.com/anoideaopen/foundation/test/chaincode/industrial"
}

// PeerTLSCACert returns the path to the local tlsca cert for the peer.
func (n *NetworkFoundation) PeerTLSCACert(p *nwo.Peer) string {
	dirName := filepath.Join(n.PeerLocalMSPDir(p), "tlscacerts")
	fileName := fmt.Sprintf("tlsca.%s-cert.pem", n.Organization(p.Organization).Domain)
	return filepath.Join(dirName, fileName)
}

// OrdererTLSCACert returns the path to the local tlsca cert for the Orderer.
func (n *NetworkFoundation) OrdererTLSCACert(o *nwo.Orderer) string {
	dirName := filepath.Join(n.OrdererLocalMSPDir(o), "tlscacerts")
	fileName := fmt.Sprintf("tlsca.%s-cert.pem", n.Organization(o.Organization).Domain)
	return filepath.Join(dirName, fileName)
}

func CtorFromSlice(s []string) string {
	sa := struct {
		Function string `json:",omitempty"`
		Args     []string
	}{}
	sa.Args = s

	b, err := json.Marshal(&sa)
	if err != nil {
		return ""
	}

	return string(b)
}
