package database

import (
	"math"
	"testing"
)

func TestValidateTrafficRate(t *testing.T) {
	for _, rate := range []float64{0.1, 1, MaxTrafficRate} {
		if err := ValidateTrafficRate(rate); err != nil {
			t.Errorf("valid rate %v rejected: %v", rate, err)
		}
	}
	for _, rate := range []float64{0, -1, MaxTrafficRate + 1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if err := ValidateTrafficRate(rate); err == nil {
			t.Errorf("invalid rate %v accepted", rate)
		}
	}
}
