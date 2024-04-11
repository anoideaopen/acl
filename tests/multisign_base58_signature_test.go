package tests

import (
	"testing"

	"github.com/anoideaopen/acl/helpers"
	"github.com/stretchr/testify/require"
)

func TestValidateMinSignatures(t *testing.T) {
	tests := []struct {
		name          string
		n             int
		expectedError string
	}{
		{
			name:          "PositiveValidN3",
			n:             3,
			expectedError: "",
		},
		{
			name:          "NegativeNEqualToMin1",
			n:             helpers.MinSignaturesRequired,
			expectedError: "invalid N '1', must be greater than 1 for multisignature transactions",
		},
		{
			name:          "NegativeNLessThanMin0",
			n:             0,
			expectedError: "invalid N '0', must be greater than 1 for multisignature transactions",
		},
		{
			name:          "NegativeNLessThanMinNegative1",
			n:             -1,
			expectedError: "invalid N '-1', must be greater than 1 for multisignature transactions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateMinSignatures(tt.n)
			if tt.expectedError != "" {
				require.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
