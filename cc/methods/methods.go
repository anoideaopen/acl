package methods

import (
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

type (
	// Method is a wrapper on methods which can have different signatures
	Method interface {
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

func New(method any) (Method, error) {
	if qMethod, ok := method.(func(shim.ChaincodeStubInterface, []string) ([]byte, error)); ok {
		return &queryMethod{
			Method: qMethod,
		}, nil
	}

	if iMethod, ok := method.(func(shim.ChaincodeStubInterface, []string) error); ok {
		return &invokeMethod{
			Method: iMethod,
		}, nil
	}

	return nil, errors.New("unknown method signature")
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
