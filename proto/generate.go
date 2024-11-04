package proto

import "github.com/hyperledger/fabric-chaincode-go/shim"

//go:generate protoc -I=. --go_out=paths=source_relative:. acl-config.proto
//go:generate counterfeiter -generate
//counterfeiter:generate -o ../tests/unit/mock/chaincode_stub.go --fake-name ChaincodeStub . chaincodeStub
type chaincodeStub interface { //nolint:unused
	shim.ChaincodeStubInterface
}

//counterfeiter:generate -o ../tests/unit/mock/state_iterator.go --fake-name StateIterator . stateIterator
type stateIterator interface { //nolint:unused
	shim.StateQueryIteratorInterface
}
