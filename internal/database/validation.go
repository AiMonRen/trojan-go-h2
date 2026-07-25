package database

import (
	"fmt"
	"math"
)

const MaxTrafficRate = 1000

func ValidateTrafficRate(rate float64) error {
	if rate <= 0 || rate > MaxTrafficRate || math.IsNaN(rate) || math.IsInf(rate, 0) {
		return fmt.Errorf("traffic rate must be finite and within (0, %d]", MaxTrafficRate)
	}
	return nil
}
