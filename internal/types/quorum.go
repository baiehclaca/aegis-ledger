package types

import "fmt"

// Quorum returns 2f+1 for a validator set of size n = 3f+1.
// Sets that are not of that form are rejected, including n > 31.
func Quorum(n int) (int, error) {
	if n < MinValidators || n > MaxValidators || (n-1)%3 != 0 {
		return 0, fmt.Errorf("types: validator count %d: %w", n, ErrInvalid)
	}
	f := (n - 1) / 3
	return 2*f + 1, nil
}
