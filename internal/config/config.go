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

var (
	ErrCfgBytesEmpty = errors.New("config bytes is empty")

	ErrAdminSKIEmpty          = "'adminSKI' is empty"
	ErrInvalidAdminSKI        = "'adminSKI' (index of args 0) is invalid - format found '%s' but expected hex encoded string"
	ErrValidatorsCountEmpty   = "'validatorsCount' is empty"
	ErrInvalidValidatorsCount = "'validatorsCount' (index of args 1) is invalid - format found '%s' but expected value with type int"
	ErrValidatorsEmpty        = "'validator #'%d'' is empty"
	ErrParsingArgsOld         = "init: parsing args old way: %s"
	ErrSavingConfig           = "init: saving config: %s"
	ErrArgsLessThanMin        = "minimum required args length is '%d', passed %d"
)

func SetConfig(stub shim.ChaincodeStubInterface) error {
	args := stub.GetStringArgs()

	var (
		cfgBytes []byte
		cfg      *proto.ACLConfig
		err      error
	)
	if IsJSONConfig(args) {
		cfgBytes = []byte(args[0])
		cfg, err = fromBytes(cfgBytes)
		if err != nil {
			return err
		}
	} else {
		// handle args as position parameters and fill config structure.
		// TODO: remove this code when all users moved to json-config initialization.
		cfg, err = ParseArgsArr(args)
		if err != nil {
			return fmt.Errorf(ErrParsingArgsOld, err)
		}
	}

	for i, validator := range cfg.Validators {
		if validator.GetPublicKey() == "" {
			cfg.Validators[i].KeyType = helpers.DefaultPublicKeyType()
		}
		// gost key can't be used as a validator's key
		if !helpers.ValidatePublicKeyType(validator.KeyType, proto.KeyType_gost.String()) {
			return fmt.Errorf("invalid key type: %s", validator.GetPublicKey())
		}
	}

	ccName, err := helpers.ParseCCName(stub)
	if err != nil {
		return fmt.Errorf("error parsing chaincode name: %w", err)
	}

	// This field should be filled automatically to compare while other chaincode invokes ACL
	cfg.CcName = ccName
	cfgBytes, err = protojson.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}

	if err = SaveConfig(stub, cfgBytes); err != nil {
		return fmt.Errorf(ErrSavingConfig, err)
	}

	return nil
}

// SaveConfig saves configuration data to the state using the provided State interface.
//
// If the provided cfgBytes slice is empty, the function returns an ErrCfgBytesEmpty error.
//
// If there is an error while saving the data to the state, an error is returned with
// additional information about the error.
func SaveConfig(stub shim.ChaincodeStubInterface, cfgBytes []byte) error {
	if len(cfgBytes) == 0 {
		return ErrCfgBytesEmpty
	}

	if err := stub.PutState(keyConfig, cfgBytes); err != nil {
		return fmt.Errorf("putting config data to state: %w", err)
	}

	return nil
}

// loadRawConfig retrieves and returns the raw configuration data from the state
// using the provided State interface.
//
// The function returns the configuration data as a byte slice and nil error if successful.
//
// If there is an error while loading the data from the state,
// an error is returned with additional information about the error.
//
// If the retrieved configuration data is empty, the function returns an ErrCfgBytesEmpty error.
func loadRawConfig(stub shim.ChaincodeStubInterface) ([]byte, error) {
	cfgBytes, err := stub.GetState(keyConfig)
	if err != nil {
		return nil, fmt.Errorf("loading raw config: %w", err)
	}
	if len(cfgBytes) == 0 {
		return nil, ErrCfgBytesEmpty
	}

	return cfgBytes, nil
}

// fromBytes parses the provided byte slice containing JSON-encoded contract configuration
// and returns a pointer to a proto.ContractConfig struct.
//
// The function uses protojson.Unmarshal to deserialize the JSON-encoded data into the *proto.ContractConfig struct.
// If the unmarshalling process fails, an error is returned with additional information about the failure.
func fromBytes(cfgBytes []byte) (*proto.ACLConfig, error) {
	var cfg proto.ACLConfig
	if err := protojson.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling failed: %w", err)
	}

	return &cfg, nil
}

// GetConfig returns config from state
func GetConfig(stub shim.ChaincodeStubInterface) (*proto.ACLConfig, error) {
	cfgBytes, err := loadRawConfig(stub)
	if err != nil {
		return nil, err
	}

	cfg, err := fromBytes(cfgBytes)
	if err != nil {
		return nil, err
	}

	return cfg, nil
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
func ParseArgsArr(args []string) (*proto.ACLConfig, error) {
	const minArgsCount = 2
	argsCount := len(args)
	if argsCount < minArgsCount {
		return nil, fmt.Errorf(ErrArgsLessThanMin,
			argsCount, minArgsCount)
	}

	if args[indexAdminSKI] == "" {
		return nil, errors.New(ErrAdminSKIEmpty)
	}
	adminSKIEncoded := args[indexAdminSKI]
	_, err := hex.DecodeString(adminSKIEncoded)
	if err != nil {
		return nil, fmt.Errorf(ErrInvalidAdminSKI, adminSKIEncoded)
	}

	if args[indexValidatorsCount] == "" {
		return nil, errors.New(ErrValidatorsCountEmpty)
	}
	validatorsCount, err := strconv.ParseInt(args[indexValidatorsCount], 10, 64)
	if err != nil {
		return nil, fmt.Errorf(ErrInvalidValidatorsCount, args[indexValidatorsCount])
	}

	lastValidatorArgIndex := indexValidators + validatorsCount

	validatorKeys := args[indexValidators:lastValidatorArgIndex]
	for i, validatorKey := range validatorKeys {
		if validatorKey == "" {
			return nil, fmt.Errorf(ErrValidatorsEmpty, i)
		}
	}

	validators := make([]*proto.ACLValidator, len(validatorKeys))
	for i, key := range validatorKeys {
		validators[i] = &proto.ACLValidator{
			PublicKey: key,
			KeyType:   helpers.DefaultPublicKeyType(),
		}
	}

	return &proto.ACLConfig{
		AdminSKIEncoded: adminSKIEncoded,
		Validators:      validators,
	}, nil
}
