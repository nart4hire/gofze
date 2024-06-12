package lib_test

import (
	"math"
	"testing"

	"github.com/nart4hire/fingerprints/lib/types"
	. "github.com/nart4hire/gofze/lib"
)

func TestEncode(t *testing.T) {
	min1 := &types.Minutiae{
		X: 2047,
		Y: 2047,
		Angle: 6.283,
		Type: types.Unknown,
	}

	m := NewMinutia(min1)

	min2 := m.Unmarshal()

	if min1.X != min2.X {
		t.Error("X does not match")
	}

	if min1.Y != min2.Y {
		t.Error("Y does not match")
	}

	if math.Abs(min1.Angle - min2.Angle) > 0.03 { // minimum delta for rounding errors
		t.Error("Angle does not match")
	}

	if min1.Type != min2.Type {
		t.Error("Type does not match")
	}
}