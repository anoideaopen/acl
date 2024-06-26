package client

import (
	"github.com/anoideaopen/foundation/test/integration/cmn/client"
	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/fabric/integration/nwo"
	. "github.com/onsi/gomega"
)

// TxInvokeWithMultisign invokes transaction to foundation fabric with multisign
func TxInvokeWithMultisign(network *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer,
	channel string, ccName string, user *UserFoundationMultisigned,
	fn string, requestID string, nonce string, args ...string) (txId string) {
	ctorArgs := append(append([]string{fn, requestID, channel, ccName}, args...), nonce)
	pubKey, sMsgsByte, err := user.Sign(ctorArgs...)
	Expect(err).NotTo(HaveOccurred())

	var sMsgsStr []string
	for _, sMsgByte := range sMsgsByte {
		sMsgsStr = append(sMsgsStr, base58.Encode(sMsgByte))
	}

	ctorArgs = append(append(ctorArgs, pubKey...), sMsgsStr...)
	return client.TxInvoke(network, peer, orderer, channel, ccName, nil, ctorArgs...)
}
