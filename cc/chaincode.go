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
		tls      shim.TLSProperties // TLS configuration properties.
	}
	ccFunc func(stub shim.ChaincodeStubInterface, args []string) peer.Response
)

func New() (*ACL, error) {
	tlsProps := shim.TLSProperties{
		Disabled: true,
	}

	key, cert, clientCACerts, err := readTLSConfigFromEnv()
	if err != nil {
		return &ACL{}, fmt.Errorf("error reading TLS config from environment: %w", err)
	}

	// If TLS configuration is found in environment variables, use it.
	if key != nil && cert != nil {
		tlsProps.Disabled = false
		tlsProps.Key = key
		tlsProps.Cert = cert
		tlsProps.ClientCACerts = clientCACerts
	}

	return &ACL{
		tls: tlsProps,
	}, nil
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
		if method.Name != "Init" && method.Name != "Invoke" && method.Name != "Start" {
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

	srv := shim.ChaincodeServer{
		CCID:     ccID,
		Address:  fmt.Sprintf("%s:%s", "0.0.0.0", port),
		CC:       c,
		TLSProps: c.tls,
	}

	return srv.Start()
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
