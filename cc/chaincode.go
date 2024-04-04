package cc

import (
	"fmt"
	"math/big"
	"reflect"
	"runtime/debug"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"gitlab.n-t.io/core/library/chaincode/acl/cc/proto"
)

type (
	ACL struct {
		init *proto.Args
	}
	ccfunc func(stub shim.ChaincodeStubInterface, args []string) peer.Response
)

func New() *ACL {
	return &ACL{}
}

// Init - method for initialize chaincode
// args: adminSKI, validatorsCount, validatorBase58Ed25519PublicKey1, ..., validatorBase58Ed25519PublicKeyN
func (c *ACL) Init(stub shim.ChaincodeStubInterface) peer.Response {
	newInitArgs, err := getNewInitArgsByChaincodeArgs(stub)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = putInitArgsToState(stub, newInitArgs)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

type Account struct {
	Address string   `json:"address"`
	Balance *big.Int `json:"balance"`
}

func (c *ACL) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic invoke\n" + string(debug.Stack()))
		}
	}()
	fn, args := stub.GetFunctionAndParameters()
	if c.init == nil {
		init, err := GetInitArgsFromState(stub)
		if err != nil {
			return shim.Error(err.Error())
		}
		if init == nil {
			return shim.Error("ACL chaincode not initialized, please invoke Init with init args first")
		}
		c.init = init
	}
	methods := make(map[string]ccfunc)
	t := reflect.TypeOf(c)
	var ok bool
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		if method.Name != "Init" && method.Name != "Invoke" {
			name := toLowerFirstLetter(method.Name)
			if methods[name], ok = reflect.ValueOf(c).MethodByName(method.Name).Interface().(func(shim.ChaincodeStubInterface, []string) peer.Response); !ok {
				return shim.Error(fmt.Sprintf("Chaincode initialization failure: cc method %s does not satisfy signature func(stub shim.ChaincodeStubInterface, args []string) peer.Response", method.Name))
			}
		}
	}

	ccinvoke, ok := methods[fn]
	if !ok {
		return shim.Error(fmt.Sprintf("unknown method %s in tx %s", fn, stub.GetTxID()))
	}

	return ccinvoke(stub, args)
}
