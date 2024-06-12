package lib_test

import (
	"testing"
	. "github.com/nart4hire/gofze/lib"
)

func TestFuzzyExtractor(t *testing.T) {
	fe := NewDefaultFuzzyExtractor(16, 8)
	if fe == nil {
		t.Error("Failed to create FuzzyExtractor")
	}

	key, helpers, err := fe.Gen("00112233445566778899aabbccddeeff")

	if err != nil {
		t.Error("Failed to generate key and helpers")
	}

	t.Log(key)

	key2, err := fe.Rep("00112223445566778899abbbccddeeff", helpers)
	if err != nil {
		t.Error("Failed to reproduce key")
	}

	t.Log(key2)

	if key != key2 {
		t.Error("Key and reproduced key do not match")
	}
}