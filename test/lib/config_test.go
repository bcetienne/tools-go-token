package lib

import (
	"testing"

	"github.com/bcetienne/tools-go-token/lib"
)

func Test_NewConfig_Success(t *testing.T) {
	// Arrange
	issuer := "test-issuer"
	jwtSecret := "super-secret-key"
	jwtExpiry := "15m"
	tokenExpiry := "24h"

	// Act
	config := lib.NewConfig(issuer, jwtSecret, jwtExpiry, &tokenExpiry)

	// Assert
	if config == nil {
		t.Fatal("NewConfig should return a non-nil Config")
	}

	if config.Issuer != issuer {
		t.Fatalf("Expected Issuer to be %s, got %s", issuer, config.Issuer)
	}

	if config.JWTSecret != jwtSecret {
		t.Fatalf("Expected JWTSecret to be %s, got %s", jwtSecret, config.JWTSecret)
	}

	if config.JWTExpiry != jwtExpiry {
		t.Fatalf("Expected JWTExpiry to be %s, got %s", jwtExpiry, config.JWTExpiry)
	}

	if config.TokenExpiry == nil {
		t.Fatal("Expected TokenExpiry to be non-nil")
	}

	if *config.TokenExpiry != tokenExpiry {
		t.Fatalf("Expected TokenExpiry to be %s, got %s", tokenExpiry, *config.TokenExpiry)
	}
}

func Test_NewConfig_WithNilTokenExpiry(t *testing.T) {
	// Arrange
	issuer := "test-issuer"
	jwtSecret := "super-secret-key"
	jwtExpiry := "15m"

	// Act
	config := lib.NewConfig(issuer, jwtSecret, jwtExpiry, nil)

	// Assert
	if config == nil {
		t.Fatal("NewConfig should return a non-nil Config")
	}

	if config.Issuer != issuer {
		t.Fatalf("Expected Issuer to be %s, got %s", issuer, config.Issuer)
	}

	if config.JWTSecret != jwtSecret {
		t.Fatalf("Expected JWTSecret to be %s, got %s", jwtSecret, config.JWTSecret)
	}

	if config.JWTExpiry != jwtExpiry {
		t.Fatalf("Expected JWTExpiry to be %s, got %s", jwtExpiry, config.JWTExpiry)
	}

	if config.TokenExpiry != nil {
		t.Fatal("Expected TokenExpiry to be nil")
	}
}

func Test_NewConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		jwtSecret   string
		jwtExpiry   string
		tokenExpiry *string
		expectValid bool
	}{
		{
			name:        "Valid config with all values",
			issuer:      "my-app",
			jwtSecret:   "my-jwt-secret-key",
			jwtExpiry:   "15m",
			tokenExpiry: stringPtr("7d"),
			expectValid: true,
		},
		{
			name:        "Valid config with nil tokenExpiry",
			issuer:      "my-app",
			jwtSecret:   "my-jwt-secret-key",
			jwtExpiry:   "30m",
			tokenExpiry: nil,
			expectValid: true,
		},
		{
			name:        "Valid config with empty strings",
			issuer:      "",
			jwtSecret:   "",
			jwtExpiry:   "",
			tokenExpiry: stringPtr(""),
			expectValid: true,
		},
		{
			name:        "Valid config with special characters",
			issuer:      "app-test@domain.com",
			jwtSecret:   "secret!@#$%^&*()",
			jwtExpiry:   "1h30m",
			tokenExpiry: stringPtr("30d"),
			expectValid: true,
		},
		{
			name:        "Valid config with long values",
			issuer:      "very-long-issuer-name-for-testing-purposes",
			jwtSecret:   "very-long-jwt-secret-key-with-many-characters-for-security",
			jwtExpiry:   "2h45m30s",
			tokenExpiry: stringPtr("720h"),
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			config := lib.NewConfig(tt.issuer, tt.jwtSecret, tt.jwtExpiry, tt.tokenExpiry)

			// Assert
			if config == nil {
				t.Fatal("NewConfig should return a non-nil Config")
			}

			if config.Issuer != tt.issuer {
				t.Fatalf("Expected Issuer to be %q, got %q", tt.issuer, config.Issuer)
			}

			if config.JWTSecret != tt.jwtSecret {
				t.Fatalf("Expected JWTSecret to be %q, got %q", tt.jwtSecret, config.JWTSecret)
			}

			if config.JWTExpiry != tt.jwtExpiry {
				t.Fatalf("Expected JWTExpiry to be %q, got %q", tt.jwtExpiry, config.JWTExpiry)
			}

			if tt.tokenExpiry == nil {
				if config.TokenExpiry != nil {
					t.Fatal("Expected TokenExpiry to be nil")
				}
			} else {
				if config.TokenExpiry == nil {
					t.Fatal("Expected TokenExpiry to be non-nil")
				}
				if *config.TokenExpiry != *tt.tokenExpiry {
					t.Fatalf("Expected TokenExpiry to be %q, got %q", *tt.tokenExpiry, *config.TokenExpiry)
				}
			}
		})
	}
}

func Test_Config_StructFields(t *testing.T) {
	tokenExpiry := "24h"
	config := &lib.Config{
		Issuer:      "test-issuer",
		JWTSecret:   "test-secret",
		JWTExpiry:   "15m",
		TokenExpiry: &tokenExpiry,
	}

	if config.Issuer == "" {
		t.Error("Issuer field should be accessible")
	}
	if config.JWTSecret == "" {
		t.Error("JWTSecret field should be accessible")
	}
	if config.JWTExpiry == "" {
		t.Error("JWTExpiry field should be accessible")
	}
	if config.TokenExpiry == nil {
		t.Error("TokenExpiry field should be accessible")
	}
}

func Test_Config_Modification(t *testing.T) {
	config := lib.NewConfig("original", "original", "original", stringPtr("original"))

	config.Issuer = "modified"
	config.JWTSecret = "modified"
	config.JWTExpiry = "modified"
	config.TokenExpiry = stringPtr("modified")

	if config.Issuer != "modified" {
		t.Error("Issuer should be modifiable")
	}
	if config.JWTSecret != "modified" {
		t.Error("JWTSecret should be modifiable")
	}
	if config.JWTExpiry != "modified" {
		t.Error("JWTExpiry should be modifiable")
	}
	if config.TokenExpiry == nil || *config.TokenExpiry != "modified" {
		t.Error("TokenExpiry should be modifiable")
	}
}

func Test_Config_TokenExpiryPointer(t *testing.T) {
	t.Run("TokenExpiry pointer behavior", func(t *testing.T) {
		tokenExpiry := "1h"
		config := lib.NewConfig("issuer", "secret", "15m", &tokenExpiry)

		tokenExpiry = "2h"

		if *config.TokenExpiry != "2h" {
			t.Fatalf("Expected TokenExpiry to change to %s, got %s", "2h", *config.TokenExpiry)
		}
	})

	t.Run("Setting TokenExpiry to nil", func(t *testing.T) {
		tokenExpiry := "1h"
		config := lib.NewConfig("issuer", "secret", "15m", &tokenExpiry)

		config.TokenExpiry = nil

		if config.TokenExpiry != nil {
			t.Error("TokenExpiry should be settable to nil")
		}
	})
}

func Test_Config_ZeroValues(t *testing.T) {
	config := lib.NewConfig("", "", "", nil)

	if config.Issuer != "" {
		t.Error("Empty string should be preserved")
	}
	if config.JWTSecret != "" {
		t.Error("Empty string should be preserved")
	}
	if config.JWTExpiry != "" {
		t.Error("Empty string should be preserved")
	}
	if config.TokenExpiry != nil {
		t.Error("Nil pointer should be preserved")
	}
}

// Utility function to create a pointer to a string
func stringPtr(s string) *string {
	return &s
}
