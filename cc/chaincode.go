package cc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"github.com/anoideaopen/acl/cc/methods"
	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/internal/config"
	"github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/foundation/core/logger"
	"github.com/anoideaopen/foundation/core/telemetry"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"go.opentelemetry.io/otel/attribute"
)

type (
	ACL struct {
		adminSKI  []byte
		config    *proto.ACLConfig
		methods   map[string]methods.Method
		methodsMu sync.RWMutex
		logger    *flogging.FabricLogger
		isService bool
		lockTH    sync.RWMutex
		trHandler *telemetry.TracingHandler

		opts opts
	}

	opts struct {
		additionalMethods map[string]methods.Method
	}

	Account struct {
		Address string   `json:"address"`
		Balance *big.Int `json:"balance"`
	}

	Option func(*opts) error
)

// WithAdditionalMethods configures the option to include additional methods for use in the application.
func WithAdditionalMethods(additionalMethods map[string]any) Option {
	return func(o *opts) error {
		o.additionalMethods = make(map[string]methods.Method)
		for name, method := range additionalMethods {
			m, err := methods.New(method)
			if err != nil {
				return err
			}
			o.additionalMethods[name] = m
		}
		return nil
	}
}

func New(options ...Option) *ACL {
	var o opts
	for _, opt := range options {
		if err := opt(&o); err != nil {
			panic(err)
		}
	}
	return &ACL{opts: o}
}

func (c *ACL) log() *flogging.FabricLogger {
	if c.logger == nil {
		c.logger = logger.Logger()
	}
	return c.logger
}

// Init - method for initialize chaincode
// args: adminSKI, validatorsCount, validatorBase58Ed25519PublicKey1, ..., validatorBase58Ed25519PublicKeyN
func (c *ACL) Init(stub shim.ChaincodeStubInterface) *peer.Response {
	stub.StartWriteBatch()

	if err := config.SetConfig(stub); err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (c *ACL) method(name string) (methods.Method, error) {
	c.methodsMu.RLock()
	defer c.methodsMu.RUnlock()
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

func (c *ACL) Invoke(stub shim.ChaincodeStubInterface) *peer.Response {
	stub.StartWriteBatch()

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

	// Need to always read the config to ensure there will be no determinism while executing the transaction
	// init config begins
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

	// Getting carrier from a transient map and creating tracing span
	_, span := c.tracingHandler().StartNewSpan(
		c.tracingHandler().ContextFromStub(stub),
		"cc.Invoke",
	)

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

	// Transaction context.
	span.AddEvent("get transactionID")
	transactionID := stub.GetTxID()

	span.SetAttributes(attribute.String("channel", stub.GetChannelID()))
	span.SetAttributes(attribute.String("tx_id", transactionID))
	span.SetAttributes(telemetry.MethodType(telemetry.MethodNbTx))

	span.AddEvent("get function")
	method, err := c.method(fn)
	if err != nil {
		errMsg := fmt.Sprintf("failed to invoke method %s: %s", fn, err.Error())
		lg.Errorf(logMessage, errMsg)
		return shim.Error(errMsg)
	}

	span.AddEvent(fmt.Sprintf("begin id: %s, method: %s", transactionID, fn))
	defer func() {
		span.AddEvent(fmt.Sprintf("end id: %s, method: %s, elapsed: %d",
			transactionID,
			fn,
			time.Since(start),
		))
		span.End()
	}()

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

	if err := c.setupMethods(); err != nil {
		return fmt.Errorf("failed setting up chaincode methods: %w", err)
	}

	if os.Getenv(chaincodeExecModeEnv) == chaincodeExecModeServer {
		return c.startAsChaincodeServer()
	}

	return c.startAsRegularChaincode()
}

func (c *ACL) setupMethods() error {
	c.methodsMu.Lock()
	aclMethods := make(map[string]methods.Method)

	t := reflect.TypeOf(c)
	for i := range t.NumMethod() {
		var (
			method = t.Method(i)
			err    error
		)

		if skipMethod(method.Name) {
			continue
		}

		aclMethods[helpers.ToLowerFirstLetter(method.Name)], err = methods.New(reflect.ValueOf(c).MethodByName(method.Name).Interface())
		if err != nil {
			return fmt.Errorf("failed adding method %s", method.Name)
		}
	}
	// Process additional methods
	// Add methods from options only if they are not already defined
	for name, method := range c.opts.additionalMethods {
		if _, ok := c.methods[name]; ok {
			continue
		}
		c.methods[name] = method
	}
	c.methods = aclMethods
	defer c.methodsMu.Unlock()
	return nil
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

	c.isService = true

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
