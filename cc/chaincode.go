package cc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
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

	// Always read the config so that there is no determinism when executing a transaction
	// init config begin
	cfg, err := config.GetConfig(stub)
	if err != nil {
		return shim.Error(err.Error())
	}
	if cfg == nil {
		return shim.Error("ACL chaincode not initialized, please invoke Init with init args first")
	}
	c.config = cfg

	adminSKI, err := hex.DecodeString(cfg.GetAdminSKIEncoded())
	if err != nil {
		return shim.Error(fmt.Sprintf(config.ErrInvalidAdminSKI, cfg.GetAdminSKIEncoded()))
	}
	c.adminSKI = adminSKI
	// init config end

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

func (c *ACL) Start() error {
	const (
		chaincodeExecModeEnv    = "CHAINCODE_EXEC_MODE"
		chaincodeExecModeServer = "server"
	)

	switch os.Getenv(chaincodeExecModeEnv) {
	case chaincodeExecModeServer:
		return c.startAsChaincodeServer()
	}

	return c.startAsRegularChaincode()
}

func (c *ACL) startAsRegularChaincode() error {
	return shim.Start(c)
}

func (c *ACL) startAsChaincodeServer() error {
	const (
		chaincodeCcIDEnv           = "CHAINCODE_ID"
		chaincodeServerPortEnv     = "CHAINCODE_SERVER_PORT"
		chaincodeServerDefaultPort = "9999"
	)

	ccID := os.Getenv(chaincodeCcIDEnv)
	if ccID == "" {
		return errors.New("need to specify chaincode id if running as a server")
	}

	port := os.Getenv(chaincodeServerPortEnv)
	if port == "" {
		port = chaincodeServerDefaultPort
	}

	srv := shim.ChaincodeServer{
		CCID:    ccID,
		Address: fmt.Sprintf("%s:%s", "0.0.0.0", port),
		CC:      c,
		TLSProps: shim.TLSProperties{
			Disabled: true,
		},
	}

	return srv.Start()
}
