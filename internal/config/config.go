package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/anoideaopen/acl/helpers"
	"github.com/anoideaopen/acl/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"google.golang.org/protobuf/encoding/protojson"
)

// keyConfig is a key for storing a configuration data in json format.
const keyConfig = "__config"

// init arguments positional indexes
const (
	indexAdminSKI int64 = iota
	indexValidatorsCount
	indexValidators
)

var ErrCfgBytesEmpty = errors.New("config bytes is empty")

// positional args specific errors
var (
	ErrAdminSKIEmpty          = "'adminSKI' is empty"
	ErrInvalidAdminSKI        = "'adminSKI' (index of args 0) is invalid - format found '%s' but expected hex encoded string"
	ErrValidatorsCountEmpty   = "'validatorsCount' is empty"
	ErrInvalidValidatorsCount = "'validatorsCount' (index of args 1) is invalid - format found '%s' but expected value with type int"
	ErrValidatorsEmpty        = "'validator #'%d'' is empty"
	ErrParsingArgsOld         = "init: parsing args old way: %s"
	ErrSavingConfig           = "init: saving config: %s"
)

func InitConfig(stub shim.ChaincodeStubInterface) ([]byte, error) {
	args := stub.GetStringArgs()

	var (
		cfgBytes []byte
		err      error
	)
	if IsJSONConfig(args) {
		cfgBytes = []byte(args[0])
	} else {
		// handle args as position parameters and fill config structure.
		// TODO: remove this code when all users moved to json-config initialization.
		cfgBytes, err = ParseArgsArr(stub, args)
		if err != nil {
			return nil, fmt.Errorf(ErrParsingArgsOld, err)
		}
	}

	if err = SaveConfig(stub, cfgBytes); err != nil {
		return nil, fmt.Errorf(ErrSavingConfig, err)
	}

	return cfgBytes, nil
}

type State interface {
	// GetState returns the value of the specified `key` from the
	// ledger. Note that GetState doesn't read data from the Write Set, which
	// has not been committed to the ledger. In other words, GetState doesn't
	// consider data modified by PutState that has not been committed.
	// If the key does not exist in the state database, (nil, nil) is returned.
	GetState(key string) ([]byte, error)

	// PutState puts the specified `key` and `value` into the transaction's
	// Write Set as a data-write proposal. PutState doesn't affect the ledger
	// until the transaction is validated and successfully committed.
	// Simple keys must not be an empty string and must not start with a
	// null character (0x00) in order to avoid range query collisions with
	// composite keys, which internally get prefixed with 0x00 as composite
	// key namespace. In addition, if using CouchDB, keys can only contain
	// valid UTF-8 strings and cannot begin with an underscore ("_").
	PutState(key string, value []byte) error
}

// SaveConfig saves configuration data to the state using the provided State interface.
//
// If the provided cfgBytes slice is empty, the function returns an ErrCfgBytesEmpty error.
//
// If there is an error while saving the data to the state, an error is returned with
// additional information about the error.
func SaveConfig(state State, cfgBytes []byte) error {
	if len(cfgBytes) == 0 {
		return ErrCfgBytesEmpty
	}

	if err := state.PutState(keyConfig, cfgBytes); err != nil {
		return fmt.Errorf("putting config data to state: %w", err)
	}

	return nil
}

// LoadRawConfig retrieves and returns the raw configuration data from the state
// using the provided State interface.
//
// The function returns the configuration data as a byte slice and nil error if successful.
//
// If there is an error while loading the data from the state,
// an error is returned with additional information about the error.
//
// If the retrieved configuration data is empty, the function returns an ErrCfgBytesEmpty error.
func LoadRawConfig(state State) ([]byte, error) {
	cfgBytes, err := state.GetState(keyConfig)
	if err != nil {
		return nil, fmt.Errorf("loading raw config: %w", err)
	}
	if len(cfgBytes) == 0 {
		return nil, ErrCfgBytesEmpty
	}

	return cfgBytes, nil
}

// FromBytes parses the provided byte slice containing JSON-encoded contract configuration
// and returns a pointer to a proto.ContractConfig struct.
//
// The function uses protojson.Unmarshal to deserialize the JSON-encoded data into the *proto.ContractConfig struct.
// If the unmarshalling process fails, an error is returned with additional information about the failure.
func FromBytes(cfgBytes []byte) (*proto.Config, error) {
	var cfg proto.Config
	if err := protojson.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling failed: %w", err)
	}

	return &cfg, nil
}

// IsJSONConfig checks if the provided arguments represent a valid JSON configuration.
//
// The function returns true if there is exactly one argument in the initialization args slice,
// and if the content of that argument is a valid JSON.
func IsJSONConfig(args []string) bool {
	return len(args) == 1 && json.Valid([]byte(args[0]))
}

// ParseArgsArr parses positional initialization arguments and generates JSON-config of []byte type.
// Accepts the channel name (chaincode) and the list of positional initialization parameters.
// Only needed to maintain backward compatibility.
// Marked for deletion after all deploy tools will be switched to JSON-config initialization of chaincodes.
// ToDo - need to be deleted after switching to json-config initialization
func ParseArgsArr(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	const minArgsCount = 2
	argsCount := len(args)
	if argsCount < minArgsCount {
		return nil, fmt.Errorf("minimum required args length is '%d', passed %d",
			argsCount, minArgsCount)
	}

	if args[indexAdminSKI] == "" {
		return nil, fmt.Errorf(ErrAdminSKIEmpty)
	}
	adminSKI, err := hex.DecodeString(args[indexAdminSKI])
	if err != nil {
		return nil, fmt.Errorf(ErrInvalidAdminSKI, args[indexAdminSKI])
	}

	if args[indexValidatorsCount] == "" {
		return nil, fmt.Errorf(ErrValidatorsCountEmpty)
	}
	validatorsCount, err := strconv.ParseInt(args[indexValidatorsCount], 10, 64)
	if err != nil {
		return nil, fmt.Errorf(ErrInvalidValidatorsCount, args[indexValidatorsCount])
	}

	lastValidatorArgIndex := indexValidators + validatorsCount

	validators := args[indexValidatorsCount:lastValidatorArgIndex]
	for i, validator := range validators {
		if validator == "" {
			return nil, fmt.Errorf(ErrValidatorsEmpty, i)
		}
	}

	ccName, err := helpers.ParseCCName(stub)
	if err != nil {
		return nil, err
	}

	cfg := &proto.Config{
		CCName:          ccName,
		AdminSKI:        adminSKI,
		ValidatorsCount: validatorsCount,
		Validators:      validators,
	}

	cfgBytes, err := protojson.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshalling config: %w", err)
	}

	return cfgBytes, nil
}
