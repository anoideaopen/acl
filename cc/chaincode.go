package cc

import (
	"encoding/hex"
	"errors"
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
		adminSKI []byte
		config   *proto.ACLConfig
	}
	ccFunc func(stub shim.ChaincodeStubInterface, args []string) peer.Response
)

func New() *ACL {
	return &ACL{}
}

// Init - method for initialize chaincode
// args: adminSKI, validatorsCount, validatorBase58Ed25519PublicKey1, ..., validatorBase58Ed25519PublicKeyN
func (c *ACL) Init(stub shim.ChaincodeStubInterface) peer.Response {
	if err := config.SetConfig(stub); err != nil {
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

	// Need to always read the config to assure there will be no determinism while executing the transaction
	if err := c.readConfig(stub); err != nil {
		return shim.Error(err.Error())
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

// readConfig reads & validates ACL config
func (c *ACL) readConfig(stub shim.ChaincodeStubInterface) error {
	cfg, err := config.GetConfig(stub)
	if err != nil {
		return err
	}
	if cfg == nil {
		return errors.New("ACL chaincode not initialized, please invoke Init with init args first")
	}

	adminSKIEncoded := cfg.GetAdminSKIEncoded()
	if adminSKIEncoded == "" {
		return errors.New(config.ErrAdminSKIEmpty)
	}

	adminSKI, err := hex.DecodeString(adminSKIEncoded)
	if err != nil {
		return fmt.Errorf(config.ErrInvalidAdminSKI, adminSKIEncoded)
	}

	c.config = cfg
	c.adminSKI = adminSKI

	return nil
}
