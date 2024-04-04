package compositekey

import "github.com/hyperledger/fabric-chaincode-go/shim"

const (
	PublicKeyPrefix           = "pk"
	SignedAddressPrefix       = "address"
	AccountInfoPrefix         = "accountinfo"
	NoncePrefix               = "nonce"
	AdditionalKeyParentPrefix = "additional_key_parent"
)

func PublicKey(stub shim.ChaincodeStubInterface, addressBase58Check string) (string, error) {
	return stub.CreateCompositeKey(
		PublicKeyPrefix,
		[]string{addressBase58Check},
	)
}

func SignedAddress(stub shim.ChaincodeStubInterface, publicKeysHashHex string) (string, error) {
	return stub.CreateCompositeKey(
		SignedAddressPrefix,
		[]string{publicKeysHashHex},
	)
}

func AccountInfo(stub shim.ChaincodeStubInterface, addressBase58Check string) (string, error) {
	return stub.CreateCompositeKey(
		AccountInfoPrefix,
		[]string{addressBase58Check},
	)
}

func Nonce(stub shim.ChaincodeStubInterface, addressBase58Check string) (string, error) {
	return stub.CreateCompositeKey(
		NoncePrefix,
		[]string{addressBase58Check},
	)
}

func AdditionalKeyParent(stub shim.ChaincodeStubInterface, publicKeyBase58 string) (string, error) {
	return stub.CreateCompositeKey(
		AdditionalKeyParentPrefix,
		[]string{publicKeyBase58},
	)
}
