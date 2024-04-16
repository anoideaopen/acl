package errs

// Access Matrix Errors
const (
	ErrUnauthorized       = "unauthorized"
	ErrArgumentsCount     = "incorrect number of arguments %d, but this method expects: '%s'"
	ErrEmptyChannelName   = "channel name is empty"
	ErrEmptyChaincodeName = "chaincode name is empty"
	ErrEmptyRoleName      = "role name is empty"
	ErrCalledNotCCOrAdmin = "unauthorized; should be called via another chaincode or by platform administrator"
	ErrCallAthFailed      = "call authorization failed, err: %s"
)

// Errors
const (
	ErrUnauthorizedMsg          = "unauthorized: %s"
	ErrCallerNotAdmin           = "caller is not an acl admin"
	ErrDuplicateSignatures      = "duplicate validators signatures are not allowed: %w"
	ErrDuplicatePubKeys         = "duplicate validators public keys are not allowed: %w"
	ErrEmptyPubKey              = "empty pub key"
	ErrEmptyAddress             = "address is empty"
	ErrAccountForAddressIsEmpty = "account info for address %s is empty"

	ErrEmptyNewKey     = "empty new key"
	ErrRecordsNotFound = "not found any records"

	ErrWrongNumberOfKeys = "N (%d) is greater then M (number of pubKeys, %d)"
)
