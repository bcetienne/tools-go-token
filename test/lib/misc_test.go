package lib

import (
	"strings"
	"testing"

	"github.com/bcetienne/tools-go-token/lib"
)

func Test_Lib_Misc_GenerateRandomString(t *testing.T) {
	t.Run("Success: Generate a random string", func(t *testing.T) {
		length := 24
		randomString, err := lib.GenerateRandomString(length)
		if err != nil {
			t.Fatal("The string should not be an error")
		}
		if len(randomString) != length {
			t.Fatalf("The string %s (length of %d) does not respect the asked length : %d", randomString, len(randomString), length)
		}
	})
}

func Test_Lib_Misc_GenerateRandomString_ZeroLength(t *testing.T) {
	t.Run("Success: Generate string with zero length", func(t *testing.T) {
		randomString, err := lib.GenerateRandomString(0)
		if err != nil {
			t.Fatal("Zero length should not produce error")
		}
		if len(randomString) != 0 {
			t.Fatalf("Expected empty string, got %s", randomString)
		}
	})
}

func Test_Lib_Misc_GenerateRandomString_Uniqueness(t *testing.T) {
	t.Run("Success: Generated strings are unique", func(t *testing.T) {
		str1, _ := lib.GenerateRandomString(32)
		str2, _ := lib.GenerateRandomString(32)
		if str1 == str2 {
			t.Fatal("Two random strings should be different")
		}
	})
}

func Test_Lib_Misc_GenerateRandomString_ValidChars(t *testing.T) {
	t.Run("Success: String contains only valid characters", func(t *testing.T) {
		validChars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
		str, _ := lib.GenerateRandomString(100)
		for _, char := range str {
			if !strings.Contains(validChars, string(char)) {
				t.Fatalf("Invalid character %c in generated string", char)
			}
		}
	})
}
