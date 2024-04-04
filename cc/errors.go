package cc

// Errors
const (
	ErrUnauthorizedMsg     = "unauthorized: %s"
	ErrCallerNotAdmin      = "caller is not an acl admin"
	ErrDuplicateSignatures = "duplicate validators signatures are not allowed: %w"
	ErrDuplicatePubKeys    = "duplicate validators public keys are not allowed: %w"
	ErrEmptyPubKey         = "empty pub key"
	ErrEmptyAddress        = "address is empty"
)
