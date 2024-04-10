package cc

import (
	"bytes"
	"fmt"
	"github.com/anoideaopen/acl/cc/errs"
	"github.com/anoideaopen/acl/helpers"
	"strconv"
	"strings"

	"github.com/anoideaopen/acl/cc/compositekey"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

// AddMultisigWithBase58Signature creates multi-signature address which operates when N of M signatures is present
// args[0] request id
// args[1] chaincodeName acl
// args[2] channelID acl
// args[3] N number of signature policy (number of sufficient signatures), M part is derived from number of public keys
// args[4] nonce
// args[5:] are the public keys and signatures base58 of all participants in the multi-wallet
// and signatures confirming the agreement of all participants with the signature policy
func (c *ACL) AddMultisigWithBase58Signature(stub shim.ChaincodeStubInterface, args []string) peer.Response { //nolint:funlen,gocognit
	argsNum := len(args)
	const minArgsCount = 7
	const chaincodeName = "acl"

	if argsNum < minArgsCount {
		return shim.Error(fmt.Sprintf("incorrect number of arguments: %d, but this method expects: address, "+
			"N (signatures required), nonce, public keys, signatures", argsNum))
	}

	if err := c.verifyAccess(stub); err != nil {
		return shim.Error(fmt.Sprintf(errs.ErrUnauthorizedMsg, err.Error()))
	}

	// args[0] is request id
	// requestId := args[0]

	chaincodeNameFromArgs := args[1]
	if chaincodeNameFromArgs != chaincodeName {
		return shim.Error("incorrect chaincode name")
	}

	channelID := args[2]
	if channelID != stub.GetChannelID() {
		return shim.Error("incorrect channel")
	}

	N, err := strconv.Atoi(args[3])
	if err != nil {
		return shim.Error(fmt.Sprintf("failed to parse N, error: %s", err.Error()))
	}
	err = helpers.ValidateMinSignatures(N)
	if err != nil {
		return shim.Error(fmt.Sprintf("addMultisigWithBase58Signature: failed to validate min signatures: %v", err))
	}

	nonce := args[4]
	pksAndSignatures := args[5:]
	lenPksAndSignatures := len(pksAndSignatures)
	if lenPksAndSignatures%2 != 0 {
		return shim.Error(fmt.Sprintf("uneven number of public keys and signatures provided: %d", lenPksAndSignatures))
	}
	pks := pksAndSignatures[:lenPksAndSignatures/2]
	signatures := pksAndSignatures[lenPksAndSignatures/2:]

	pksNumber := len(pks)
	signaturesNumber := len(signatures)

	// number of pks should be equal to number of signatures
	if pksNumber != signaturesNumber {
		return shim.Error(fmt.Sprintf("multisig signature policy can't be created, number of public keys (%d) does not match number of signatures (%d)", pksNumber, signaturesNumber))
	}
	// N shouldn't be greater than number of public keys (M part of signature policy)
	if N > pksNumber {
		return shim.Error(fmt.Sprintf("N (%d) is greater then M (number of pubkeys, %d)", N, pksNumber))
	}

	message := sha3.Sum256([]byte(strings.Join(append(append([]string{"addMultisigWithBase58Signature"}, args[0:5]...), pks...), "")))

	for _, pk := range pks {
		// check the presence of multisig members in the black and gray list
		if err = checkBlocked(stub, pk); err != nil {
			return shim.Error(err.Error())
		}
	}

	if err = helpers.CheckKeysArr(pks); err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%v'", err.Error(), pks))
	}
	hashedHexKeys, err := helpers.KeyStringToSortedHashedHex(pks)
	if err != nil {
		return shim.Error(fmt.Sprintf("%s, input: '%s'", err.Error(), args[3]))
	}

	pksDecodedOriginalOrder := make([][]byte, 0, len(pks))
	for _, encodedBase58PublicKey := range pks {
		decodedPublicKey, err := helpers.DecodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return shim.Error(err.Error())
		}
		pksDecodedOriginalOrder = append(pksDecodedOriginalOrder, decodedPublicKey)
	}

	// derive address from hash of sorted base58-(DE)coded public keys
	keysArrSorted, err := helpers.DecodeAndSort(strings.Join(pks, "/"))
	if err != nil {
		return shim.Error(err.Error())
	}
	hashedPksSortedOrder := sha3.Sum256(bytes.Join(keysArrSorted, []byte("")))
	addr := base58.CheckEncode(hashedPksSortedOrder[1:], hashedPksSortedOrder[0])

	if err = checkNonce(stub, addr, nonce); err != nil {
		return shim.Error(err.Error())
	}

	if err = checkNOutMSigneBase58Signature(len(pksDecodedOriginalOrder), message[:], pksDecodedOriginalOrder, signatures); err != nil {
		return shim.Error(err.Error())
	}

	// check multisig address doesn't already exist
	pkToAddrCompositeKey, err := compositekey.SignedAddress(stub, hashedHexKeys)
	if err != nil {
		return shim.Error(err.Error())
	}

	addrAlreadyInLedgerBytes, err := stub.GetState(pkToAddrCompositeKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	addrAlreadyInLedger := &pb.SignedAddress{}
	err = proto.Unmarshal(addrAlreadyInLedgerBytes, addrAlreadyInLedger)
	if err != nil {
		return shim.Error(err.Error())
	}
	if len(addrAlreadyInLedgerBytes) != 0 {
		return shim.Error(fmt.Sprintf("The address %s associated with key %s already exists", addrAlreadyInLedger.Address.AddrString(), hashedHexKeys))
	}

	addrToPkCompositeKey, err := compositekey.PublicKey(stub, addr)
	if err != nil {
		return shim.Error(err.Error())
	}

	pksDecodedOrigOrder := make([][]byte, 0, len(pks))
	for _, encodedBase58PublicKey := range pks {
		decodedPublicKey, err := helpers.DecodeBase58PublicKey(encodedBase58PublicKey)
		if err != nil {
			return shim.Error(err.Error())
		}
		pksDecodedOrigOrder = append(pksDecodedOrigOrder, decodedPublicKey)
	}

	signedAddr, err := proto.Marshal(&pb.SignedAddress{
		Address: &pb.Address{
			UserID:       "",
			Address:      hashedPksSortedOrder[:],
			IsIndustrial: false,
			IsMultisig:   true,
		},
		SignedTx: append(append(append([]string{"addMultisigWithBase58Signature"}, args[0:5]...), pks...), signatures...),
		SignaturePolicy: &pb.SignaturePolicy{
			N:       uint32(N),
			PubKeys: pksDecodedOrigOrder,
		},
	})
	if err != nil {
		return shim.Error(err.Error())
	}

	// save multisig pk -> addr mapping
	if err = stub.PutState(pkToAddrCompositeKey, signedAddr); err != nil {
		return shim.Error(err.Error())
	}

	// save multisig address -> pk mapping
	if err = stub.PutState(addrToPkCompositeKey, []byte(hashedHexKeys)); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func checkNOutMSigneBase58Signature(n int, message []byte, pks [][]byte, signatures []string) error {
	if err := helpers.CheckDuplicates(signatures); err != nil {
		return fmt.Errorf(errs.ErrDuplicateSignatures, err)
	}

	strPubKeys := make([]string, 0, len(pks))
	for _, pk := range pks {
		strPubKeys = append(strPubKeys, base58.Encode(pk))
	}

	if err := helpers.CheckDuplicates(strPubKeys); err != nil {
		return fmt.Errorf(errs.ErrDuplicatePubKeys, err)
	}

	countSigned := 0
	for i, pk := range pks {
		// check signature
		decodedSignature := base58.Decode(signatures[i])
		if !ed25519.Verify(pk, message, decodedSignature) {
			return errors.Errorf("the signature %s does not match the public key %s", signatures[i], base58.Encode(pk))
		}
		countSigned++
	}

	if countSigned < n {
		return errors.Errorf("%d of %d signed", countSigned, n)
	}
	return nil
}
