package cc

// Errors
const (
	ErrUnauthorizedMsg     = "unauthorized: %s"
	ErrCallerNotAdmin      = "caller is not an acl admin"
	ErrDuplicateSignatures = "dublicate validators signatures are not allowed %v"
	ErrDuplicatePubKeys    = "dublicate validators public keys are not allowed %v"
	ErrEmptyPubKey         = "empty pub key"
	ErrEmptyAddress        = "address is empty"
)
