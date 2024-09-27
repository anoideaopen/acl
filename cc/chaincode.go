package cc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"runtime/debug"
	"time"

	"github.com/anoideaopen/acl/cc/methods"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/internal/config"
	"github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/foundation/core/logger"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/op/go-logging"
)

type (
	ACL struct {
		adminSKI []byte
		config   *proto.ACLConfig
		methods  map[string]methods.Method
		logger   *logging.Logger
	}

	Account struct {
		Address string   `json:"address"`
		Balance *big.Int `json:"balance"`
	}
)

func New() *ACL {
	return &ACL{}
}

func (c *ACL) log() *logging.Logger {
	if c.logger == nil {
		c.logger = logger.Logger()
	}
	return c.logger
}

// Init - method for initialize chaincode
// args: adminSKI, validatorsCount, validatorBase58Ed25519PublicKey1, ..., validatorBase58Ed25519PublicKeyN
func (c *ACL) Init(stub shim.ChaincodeStubInterface) peer.Response {
	if err := config.SetConfig(stub); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (c *ACL) method(name string) (methods.Method, error) {
	if c.methods == nil {
		aclMethods := make(map[string]methods.Method)

		t := reflect.TypeOf(c)
		for i := 0; i < t.NumMethod(); i++ {
			var (
				method = t.Method(i)
				err    error
			)

			if skipMethod(method.Name) {
				continue
			}

			aclMethods[helpers.ToLowerFirstLetter(method.Name)], err = methods.New(reflect.ValueOf(c).MethodByName(method.Name).Interface())
			if err != nil {
				return nil, fmt.Errorf("failed adding method %s", method.Name)
			}
		}
		c.methods = aclMethods
	}

	if method, ok := c.methods[name]; ok {
		return method, nil
	}

	return nil, fmt.Errorf("unknown method %s", name)
}

func skipMethod(name string) bool {
	switch name {
	case "Init", "Invoke", "Start":
		return true
	default:
		return false
	}
}

func (c *ACL) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	var (
		fn, args   = stub.GetFunctionAndParameters()
		lg         = c.log()
		logMessage = "txID: " + stub.GetTxID() + ": %s"
		start      = time.Now()
	)

	defer func() {
		if r := recover(); r != nil {
			lg.Criticalf("panic invoke\n%s", string(debug.Stack()))
		}
	}()

	defer func() {
		lg.Infof(logMessage, fmt.Sprintf("elapsed: %s", time.Since(start)))
	}()

	// Need to always read the config to assure there will be no determinism while executing the transaction
	// init config begin
	cfg, err := config.GetConfig(stub)
	if err != nil {
		errMsg := "failed getting chaincode config: " + err.Error()
		lg.Errorf(logMessage, errMsg)
		return shim.Error(errMsg)
	}
	if cfg == nil {
		errMsg := "ACL chaincode not initialized, please invoke Init with init args first"
		lg.Errorf(logMessage, errMsg)
		return shim.Error(errMsg)
	}
	c.config = cfg

	ccName, err := helpers.ParseCCName(stub)
	if err != nil {
		errMsg := "failed parsing chaincode name: " + err.Error()
		lg.Errorf(logMessage, errMsg)
		return shim.Error(errMsg)
	}

	if ccName != c.config.GetCcName() {
		lg.Infof(logMessage, fmt.Sprintf("invoke method %s from chaincode %s", fn, ccName))
	} else {
		lg.Infof(logMessage, "invoke method "+fn)
	}

	adminSKI, err := hex.DecodeString(cfg.GetAdminSKIEncoded())
	if err != nil {
		errMsg := fmt.Sprintf(config.ErrInvalidAdminSKI, cfg.GetAdminSKIEncoded())
		lg.Errorf(logMessage, errMsg)
		return shim.Error(errMsg)
	}
	c.adminSKI = adminSKI
	// init config end

	method, err := c.method(fn)
	if err != nil {
		errMsg := fmt.Sprintf("failed to invoke method %s: %s", fn, err.Error())
		lg.Errorf(logMessage, errMsg)
		return shim.Error(errMsg)
	}

	payload, err := method.Call(stub, args)
	if err != nil {
		errMsg := fmt.Sprintf("failed invoking method %s: %s", fn, err.Error())
		lg.Errorf(logMessage, errMsg)
		return shim.Error(errMsg)
	}

	return shim.Success(payload)
}

func (c *ACL) Start() error {
	const (
		chaincodeExecModeEnv    = "CHAINCODE_EXEC_MODE"
		chaincodeExecModeServer = "server"
	)

	if os.Getenv(chaincodeExecModeEnv) == chaincodeExecModeServer {
		return c.startAsChaincodeServer()
	}

	return c.startAsRegularChaincode()
}

func (c *ACL) startAsRegularChaincode() error {
	return shim.Start(c)
}

// startAsChaincodeServer creates a chaincode server without TLS.
// Support of TLS should be implemented if required
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

	tlsProps, err := tlsProperties()
	if err != nil {
		return fmt.Errorf("failed obtaining tls properties for chaincode server: %w", err)
	}

	srv := shim.ChaincodeServer{
		CCID:     ccID,
		Address:  fmt.Sprintf("%s:%s", "0.0.0.0", port),
		CC:       c,
		TLSProps: tlsProps,
	}

	return srv.Start()
}

func tlsProperties() (shim.TLSProperties, error) {
	tlsProps := shim.TLSProperties{
		Disabled: true,
	}

	key, cert, clientCACerts, err := readTLSConfigFromEnv()
	if err != nil {
		return tlsProps, fmt.Errorf("error reading TLS config from environment: %w", err)
	}

	// If TLS configuration is found in environment variables, use it.
	if key != nil && cert != nil {
		tlsProps.Disabled = false
		tlsProps.Key = key
		tlsProps.Cert = cert
		tlsProps.ClientCACerts = clientCACerts
	}

	return tlsProps, nil
}

// readTLSConfigFromEnv tries to read TLS configuration from environment variables.
func readTLSConfigFromEnv() ([]byte, []byte, []byte, error) {
	const (
		// TLS environment variables for the chaincode's TLS configuration with files.
		// tlsKeyFileEnv is the environment variable that specifies the private key file for TLS communication.
		tlsKeyFileEnv = "CHAINCODE_TLS_KEY_FILE"
		// tlsCertFileEnv is the environment variable that specifies the public key certificate file for TLS communication.
		tlsCertFileEnv = "CHAINCODE_TLS_CERT_FILE"
		// tlsClientCACertsFileEnv is the environment variable that specifies the client CA certificates file for TLS communication.
		tlsClientCACertsFileEnv = "CHAINCODE_TLS_CLIENT_CA_CERTS_FILE"

		// TLS environment variables for the chaincode's TLS configuration, directly from ENVs.
		// tlsKeyEnv is the environment variable that specifies the private key for TLS communication.
		tlsKeyEnv = "CHAINCODE_TLS_KEY"
		// tlsCertEnv is the environment variable that specifies the public key certificate for TLS communication.
		tlsCertEnv = "CHAINCODE_TLS_CERT"
		// tlsClientCACertsEnv is the environment variable that specifies the client CA certificates for TLS communication.
		tlsClientCACertsEnv = "CHAINCODE_TLS_CLIENT_CA_CERTS"
	)

	var (
		key, cert, clientCACerts []byte
		err                      error
	)

	if keyEnv := os.Getenv(tlsKeyEnv); keyEnv != "" {
		key = []byte(keyEnv)
	} else if keyFile := os.Getenv(tlsKeyFileEnv); keyFile != "" {
		key, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read TLS key file: %w", err)
		}
	}

	if certEnv := os.Getenv(tlsCertEnv); certEnv != "" {
		cert = []byte(certEnv)
	} else if certFile := os.Getenv(tlsCertFileEnv); certFile != "" {
		cert, err = os.ReadFile(certFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read TLS certificate file: %w", err)
		}
	}

	if caCertsEnv := os.Getenv(tlsClientCACertsEnv); caCertsEnv != "" {
		clientCACerts = []byte(caCertsEnv)
	} else if caCertsFile := os.Getenv(tlsClientCACertsFileEnv); caCertsFile != "" {
		clientCACerts, err = os.ReadFile(caCertsFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read client CA certificates file: %w", err)
		}
	}

	return key, cert, clientCACerts, nil
}
