package helpers

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/stretchr/testify/require"
)

const (
	encodedBase58PublicKey = "3yhRkdjUeeuQZj6qsVydXW5yD951H3KNJaGAe4YJjEiS"
	encodedHexPublicKey    = "2c3d9c1f06cd582f1becbaa6bb81410b5c8ff4153ab12dfd8c9ecc1c24067d77"
)

func TestDecodeBase58PublicKey(t *testing.T) {
	t.Run("NEGATIVE. SHOULD RETURN error WHEN encodedBase58PublicKey is empty", func(t *testing.T) {
		key, err := DecodeBase58PublicKey("")
		require.EqualError(t, err, "encoded base 58 public key is empty")
		require.Len(t, key, 0)
	})

	t.Run("NEGATIVE. SHOULD RETURN error WHEN encodedBase58PublicKey wrong text", func(t *testing.T) {
		key, err := DecodeBase58PublicKey("wrong key - text")
		require.ErrorContains(t, err, "incorrect len of decoded from base58 public key")
		require.Len(t, key, 0)
	})

	t.Run("NEGATIVE. SHOULD RETURN error WHEN encodedBase58PublicKey in hex", func(t *testing.T) {
		key, err := DecodeBase58PublicKey(encodedHexPublicKey)
		require.ErrorContains(t, err, fmt.Sprintf("incorrect len of decoded from base58 public key"))
		require.Len(t, key, 0)
	})

	t.Run("POSITIVE. SHOULD RETURN endorsement descriptor WHEN encodedBase58PublicKey in base58 format", func(t *testing.T) {
		expected := base58.Decode(encodedBase58PublicKey)
		key, err := DecodeBase58PublicKey(encodedBase58PublicKey)
		require.NoError(t, err)
		require.Equal(t, expected, key)
	})
}

func TestCheckDuplicates(t *testing.T) {
	tests := []struct {
		name          string
		input         []string
		isErrExpected bool
	}{
		{"NoDuplicates", []string{"a", "b", "c"}, false},
		{"SingleDuplicate", []string{"a", "b", "c", "a"}, true},
		{"MultipleDuplicates", []string{"a", "b", "c", "a", "b", "c"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckDuplicates(tt.input)
			if tt.isErrExpected {
				require.Error(t, err)
			}
		})
	}
}

func BenchmarkCheckDuplicates(b *testing.B) {
	input := []string{"a", "b", "c", "a", "b", "c", "b", "c", "a", "b", "c", "b", "c", "a", "b", "c"}
	var r []string
	for range 1000 {
		r = append(r, input...)
	}
	for i := 0; i < b.N; i++ {
		_ = CheckDuplicates(r)
	}
}
