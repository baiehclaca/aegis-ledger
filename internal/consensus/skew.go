package consensus

import "math"

// withinSkew reports whether claimed is within skew of now. The bounds
// saturate at the edges of int64 so a large skew cannot overflow the
// comparison.
func withinSkew(now, claimed, skew int64) bool {
	if skew < 0 {
		return false
	}
	low := int64(math.MinInt64)
	if now >= math.MinInt64+skew {
		low = now - skew
	}
	high := int64(math.MaxInt64)
	if now <= math.MaxInt64-skew {
		high = now + skew
	}
	return claimed >= low && claimed <= high
}
