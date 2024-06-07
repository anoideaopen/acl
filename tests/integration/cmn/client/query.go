package client

import (
	"time"

	"github.com/anoideaopen/acl/tests/integration/cmn"
	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

type CheckResultFunc func(err error, exitCode int, sessError []byte, sessOut []byte) string

//	func exampleCheck() CheckResultFunc {
//		return func(err error, sessExitCode int, sessError []byte, sessOut []byte) string {
//			if err != nil {
//				return fmt.Sprintf("error executing command: %v", err)
//			}
//
//			if sessExitCode != 0 {
//				return fmt.Sprintf("exit code is %d: %s, %v", sessExitCode, string(sessError), err)
//			}
//
//			out := sessOut[:len(sessOut)-1] // skip line feed
//			resp := &pb.Response{}
//			err = proto.Unmarshal(out, resp)
//			if err != nil {
//				return fmt.Sprintf("failed to unmarshal response: %v", err)
//			}
//
//			// check response
//			if ... != ... {
//				return fmt.Sprintf("error: expected %s, received %s", ..., ...)
//			}
//
//			return ""
//		}
//	}

// Query func for query from foundation fabric
func Query(network *nwo.Network, peer *nwo.Peer, channel string, ccName string,
	checkResultFunc CheckResultFunc, args ...string) {
	Eventually(func() string {
		sess, err := network.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
			ChannelID: channel,
			Name:      ccName,
			Ctor:      cmn.CtorFromSlice(args),
		})
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit())

		return checkResultFunc(err, sess.ExitCode(), sess.Err.Contents(), sess.Out.Contents())
	}, network.EventuallyTimeout, time.Second).Should(BeEmpty())
}

// QueryWithSign func for query with sign from foundation fabric
func QueryWithSign(network *nwo.Network, peer *nwo.Peer, channel string, ccName string,
	checkResultFunc CheckResultFunc, user *UserFoundation,
	fn string, requestID string, nonce string, args ...string) {
	ctorArgs := append(append([]string{fn, requestID, channel, ccName}, args...), nonce)
	pubKey, sMsg, err := user.Sign(ctorArgs...)
	Expect(err).NotTo(HaveOccurred())

	ctorArgs = append(ctorArgs, pubKey, base58.Encode(sMsg))
	Query(network, peer, channel, ccName, checkResultFunc, ctorArgs...)
}
