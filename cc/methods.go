package cc

import (
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
)

type (
	// ACLMethod is a wrapper on methods which can have different signatures
	ACLMethod interface {
		Call(stub shim.ChaincodeStubInterface, args []string) (payload []byte, err error)
	}

	queryMethod struct {
		Method queryFunc
	}

	invokeMethod struct {
		Method invokeFunc
	}

	invokeFunc func(stub shim.ChaincodeStubInterface, args []string) error
	queryFunc  func(stub shim.ChaincodeStubInterface, args []string) ([]byte, error)
)

func NewInvokeMethod(method invokeFunc) ACLMethod {
	return &invokeMethod{
		Method: method,
	}
}

func NewQueryMethod(method queryFunc) ACLMethod {
	return &queryMethod{
		Method: method,
	}
}

func (m *invokeMethod) Call(stub shim.ChaincodeStubInterface, args []string) (payload []byte, err error) {
	err = m.Method(stub, args)
	if err != nil {
		return nil, fmt.Errorf("invoke method error: %w", err)
	}
	return
}

func (m *queryMethod) Call(stub shim.ChaincodeStubInterface, args []string) (payload []byte, err error) {
	payload, err = m.Method(stub, args)
	if err != nil {
		return nil, fmt.Errorf("invoke method error: %w", err)
	}
	return
}
