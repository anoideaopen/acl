package cc

import (
	"fmt"
	"math/big"
	"reflect"
	"runtime/debug"

	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/internal/config"
	"github.com/anoideaopen/acl/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

type (
	ACL struct {
		config *proto.ACLConfig
	}
	ccFunc func(stub shim.ChaincodeStubInterface, args []string) peer.Response
)

func New() *ACL {
	return &ACL{}
}

// Init - method for initialize chaincode
// args: adminSKI, validatorsCount, validatorBase58Ed25519PublicKey1, ..., validatorBase58Ed25519PublicKeyN
func (c *ACL) Init(stub shim.ChaincodeStubInterface) peer.Response {
	cfg, err := config.InitConfig(stub)
	if err != nil {
		return shim.Error(err.Error())
	}

	c.config = cfg

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
	if c.config == nil {
		cfg, err := config.InitConfig(stub)
		if err != nil {
			return shim.Error(err.Error())
		}
		c.config = cfg
	}
	methods := make(map[string]ccFunc)
	t := reflect.TypeOf(c)
	var ok bool
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		if method.Name != "Init" && method.Name != "Invoke" {
			name := helpers.ToLowerFirstLetter(method.Name)
			if methods[name], ok = reflect.ValueOf(c).MethodByName(method.Name).Interface().(func(shim.ChaincodeStubInterface, []string) peer.Response); !ok {
				return shim.Error(fmt.Sprintf("Chaincode initialization failure: cc method %s does not satisfy signature func(stub shim.ChaincodeStubInterface, args []string) peer.Response", method.Name))
			}
		}
	}

	ccInvoke, ok := methods[fn]
	if !ok {
		return shim.Error(fmt.Sprintf("unknown method %s in tx %s", fn, stub.GetTxID()))
	}

	return ccInvoke(stub, args)
}
