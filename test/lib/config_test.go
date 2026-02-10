package lib

import (
	"testing"

	"github.com/bcetienne/tools-go-token/v4/lib"
)

func Test_NewConfig_Success(t *testing.T) {
	// Arrange
	issuer := "test-issuer"
	jwtSecret := "super-secret-key"
	jwtExpiry := "15m"
	redisAddr := "localhost:6379"
	redisPwd := "password"
	redisDB := 0
	refreshTokenTTL := "1h"
	passwordResetTTL := "10m"

	// Act
	config := lib.NewConfig(issuer, jwtSecret, jwtExpiry, redisAddr, redisPwd, "", redisDB, &refreshTokenTTL, &passwordResetTTL, nil)

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

	if config.RedisAddr != redisAddr {
		t.Fatalf("Expected RedisAddr to be %s, got %s", redisAddr, config.RedisAddr)
	}

	if config.RedisPwd != redisPwd {
		t.Fatalf("Expected RedisPwd to be %s, got %s", redisPwd, config.RedisPwd)
	}

	if config.RedisDB != redisDB {
		t.Fatalf("Expected RedisDB to be %d, got %d", redisDB, config.RedisDB)
	}

	if config.RefreshTokenTTL == nil {
		t.Fatal("Expected RefreshTokenTTL to be non-nil")
	}

	if *config.RefreshTokenTTL != refreshTokenTTL {
		t.Fatalf("Expected RefreshTokenTTL to be %s, got %s", refreshTokenTTL, *config.RefreshTokenTTL)
	}

	if config.PasswordResetTTL == nil {
		t.Fatal("Expected PasswordResetTTL to be non-nil")
	}

	if *config.PasswordResetTTL != passwordResetTTL {
		t.Fatalf("Expected PasswordResetTTL to be %s, got %s", passwordResetTTL, *config.PasswordResetTTL)
	}
}

func Test_NewConfig_WithNilTTLs(t *testing.T) {
	// Arrange
	issuer := "test-issuer"
	jwtSecret := "super-secret-key"
	jwtExpiry := "15m"
	redisAddr := "localhost:6379"
	redisPwd := "password"
	redisDB := 0

	// Act
	config := lib.NewConfig(issuer, jwtSecret, jwtExpiry, redisAddr, redisPwd, "", redisDB, nil, nil, nil)

	// Assert
	if config == nil {
		t.Fatal("NewConfig should return a non-nil Config")
	}

	// When nil, NewConfig should set default values
	if config.RefreshTokenTTL == nil {
		t.Fatal("Expected RefreshTokenTTL to have default value")
	}

	if *config.RefreshTokenTTL != "1h" {
		t.Fatalf("Expected RefreshTokenTTL default to be 1h, got %s", *config.RefreshTokenTTL)
	}

	if config.PasswordResetTTL == nil {
		t.Fatal("Expected PasswordResetTTL to have default value")
	}

	if *config.PasswordResetTTL != "10m" {
		t.Fatalf("Expected PasswordResetTTL default to be 10m, got %s", *config.PasswordResetTTL)
	}
}

func Test_NewConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		issuer           string
		jwtSecret        string
		jwtExpiry        string
		redisAddr        string
		redisPwd         string
		redisDB          int
		refreshTokenTTL  *string
		passwordResetTTL *string
		expectValid      bool
	}{
		{
			name:             "Valid config with all values",
			issuer:           "my-app",
			jwtSecret:        "my-jwt-secret-key",
			jwtExpiry:        "15m",
			redisAddr:        "localhost:6379",
			redisPwd:         "password",
			redisDB:          0,
			refreshTokenTTL:  stringPtr("24h"),
			passwordResetTTL: stringPtr("30m"),
			expectValid:      true,
		},
		{
			name:             "Valid config with nil TTLs (should use defaults)",
			issuer:           "my-app",
			jwtSecret:        "my-jwt-secret-key",
			jwtExpiry:        "30m",
			redisAddr:        "redis.example.com:6379",
			redisPwd:         "",
			redisDB:          1,
			refreshTokenTTL:  nil,
			passwordResetTTL: nil,
			expectValid:      true,
		},
		{
			name:             "Valid config with empty strings",
			issuer:           "",
			jwtSecret:        "",
			jwtExpiry:        "",
			redisAddr:        "",
			redisPwd:         "",
			redisDB:          0,
			refreshTokenTTL:  stringPtr(""),
			passwordResetTTL: stringPtr(""),
			expectValid:      true,
		},
		{
			name:             "Valid config with special characters",
			issuer:           "app-test@domain.com",
			jwtSecret:        "secret!@#$%^&*()",
			jwtExpiry:        "1h30m",
			redisAddr:        "redis://localhost:6379",
			redisPwd:         "p@ssw0rd!",
			redisDB:          5,
			refreshTokenTTL:  stringPtr("30d"),
			passwordResetTTL: stringPtr("1h"),
			expectValid:      true,
		},
		{
			name:             "Valid config with long values",
			issuer:           "very-long-issuer-name-for-testing-purposes",
			jwtSecret:        "very-long-jwt-secret-key-with-many-characters-for-security",
			jwtExpiry:        "2h45m30s",
			redisAddr:        "redis-cluster.example.com:6379",
			redisPwd:         "very-secure-password-123",
			redisDB:          15,
			refreshTokenTTL:  stringPtr("720h"),
			passwordResetTTL: stringPtr("2h"),
			expectValid:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			config := lib.NewConfig(tt.issuer, tt.jwtSecret, tt.jwtExpiry, tt.redisAddr, tt.redisPwd, "", tt.redisDB, tt.refreshTokenTTL, tt.passwordResetTTL, nil)

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

			if config.RedisAddr != tt.redisAddr {
				t.Fatalf("Expected RedisAddr to be %q, got %q", tt.redisAddr, config.RedisAddr)
			}

			if config.RedisPwd != tt.redisPwd {
				t.Fatalf("Expected RedisPwd to be %q, got %q", tt.redisPwd, config.RedisPwd)
			}

			if config.RedisDB != tt.redisDB {
				t.Fatalf("Expected RedisDB to be %d, got %d", tt.redisDB, config.RedisDB)
			}

			// Check RefreshTokenTTL
			if tt.refreshTokenTTL == nil {
				// Should have default value
				if config.RefreshTokenTTL == nil {
					t.Fatal("Expected RefreshTokenTTL to have default value")
				}
				if *config.RefreshTokenTTL != "1h" {
					t.Fatalf("Expected RefreshTokenTTL default to be 1h, got %q", *config.RefreshTokenTTL)
				}
			} else {
				if config.RefreshTokenTTL == nil {
					t.Fatal("Expected RefreshTokenTTL to be non-nil")
				}
				if *config.RefreshTokenTTL != *tt.refreshTokenTTL {
					t.Fatalf("Expected RefreshTokenTTL to be %q, got %q", *tt.refreshTokenTTL, *config.RefreshTokenTTL)
				}
			}

			// Check PasswordResetTTL
			if tt.passwordResetTTL == nil {
				// Should have default value
				if config.PasswordResetTTL == nil {
					t.Fatal("Expected PasswordResetTTL to have default value")
				}
				if *config.PasswordResetTTL != "10m" {
					t.Fatalf("Expected PasswordResetTTL default to be 10m, got %q", *config.PasswordResetTTL)
				}
			} else {
				if config.PasswordResetTTL == nil {
					t.Fatal("Expected PasswordResetTTL to be non-nil")
				}
				if *config.PasswordResetTTL != *tt.passwordResetTTL {
					t.Fatalf("Expected PasswordResetTTL to be %q, got %q", *tt.passwordResetTTL, *config.PasswordResetTTL)
				}
			}
		})
	}
}

func Test_Config_StructFields(t *testing.T) {
	refreshTokenTTL := "24h"
	passwordResetTTL := "10m"
	config := &lib.Config{
		Issuer:           "test-issuer",
		JWTSecret:        "test-secret",
		JWTExpiry:        "15m",
		RedisAddr:        "localhost:6379",
		RedisPwd:         "password",
		RedisDB:          0,
		RefreshTokenTTL:  &refreshTokenTTL,
		PasswordResetTTL: &passwordResetTTL,
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
	if config.RedisAddr == "" {
		t.Error("RedisAddr field should be accessible")
	}
	if config.RedisPwd == "" {
		t.Error("RedisPwd field should be accessible")
	}
	if config.RefreshTokenTTL == nil {
		t.Error("RefreshTokenTTL field should be accessible")
	}
	if config.PasswordResetTTL == nil {
		t.Error("PasswordResetTTL field should be accessible")
	}
}

func Test_Config_Modification(t *testing.T) {
	config := lib.NewConfig("original", "original", "original", "original", "original", "", 0, stringPtr("original"), stringPtr("original"), nil)

	config.Issuer = "modified"
	config.JWTSecret = "modified"
	config.JWTExpiry = "modified"
	config.RedisAddr = "modified"
	config.RedisPwd = "modified"
	config.RedisDB = 99
	config.RefreshTokenTTL = stringPtr("modified")
	config.PasswordResetTTL = stringPtr("modified")

	if config.Issuer != "modified" {
		t.Error("Issuer should be modifiable")
	}
	if config.JWTSecret != "modified" {
		t.Error("JWTSecret should be modifiable")
	}
	if config.JWTExpiry != "modified" {
		t.Error("JWTExpiry should be modifiable")
	}
	if config.RedisAddr != "modified" {
		t.Error("RedisAddr should be modifiable")
	}
	if config.RedisPwd != "modified" {
		t.Error("RedisPwd should be modifiable")
	}
	if config.RedisDB != 99 {
		t.Error("RedisDB should be modifiable")
	}
	if config.RefreshTokenTTL == nil || *config.RefreshTokenTTL != "modified" {
		t.Error("RefreshTokenTTL should be modifiable")
	}
	if config.PasswordResetTTL == nil || *config.PasswordResetTTL != "modified" {
		t.Error("PasswordResetTTL should be modifiable")
	}
}

func Test_Config_TTLPointers(t *testing.T) {
	t.Run("RefreshTokenTTL pointer behavior", func(t *testing.T) {
		refreshTokenTTL := "1h"
		passwordResetTTL := "10m"
		config := lib.NewConfig("issuer", "secret", "15m", "localhost:6379", "", "", 0, &refreshTokenTTL, &passwordResetTTL, nil)

		refreshTokenTTL = "2h"

		if *config.RefreshTokenTTL != "2h" {
			t.Fatalf("Expected RefreshTokenTTL to change to %s, got %s", "2h", *config.RefreshTokenTTL)
		}
	})

	t.Run("PasswordResetTTL pointer behavior", func(t *testing.T) {
		refreshTokenTTL := "1h"
		passwordResetTTL := "10m"
		config := lib.NewConfig("issuer", "secret", "15m", "localhost:6379", "", "", 0, &refreshTokenTTL, &passwordResetTTL, nil)

		passwordResetTTL = "30m"

		if *config.PasswordResetTTL != "30m" {
			t.Fatalf("Expected PasswordResetTTL to change to %s, got %s", "30m", *config.PasswordResetTTL)
		}
	})

	t.Run("Setting TTLs to nil", func(t *testing.T) {
		refreshTokenTTL := "1h"
		passwordResetTTL := "10m"
		config := lib.NewConfig("issuer", "secret", "15m", "localhost:6379", "", "", 0, &refreshTokenTTL, &passwordResetTTL, nil)

		config.RefreshTokenTTL = nil
		config.PasswordResetTTL = nil

		if config.RefreshTokenTTL != nil {
			t.Error("RefreshTokenTTL should be settable to nil")
		}
		if config.PasswordResetTTL != nil {
			t.Error("PasswordResetTTL should be settable to nil")
		}
	})
}

func Test_Config_ZeroValues(t *testing.T) {
	config := lib.NewConfig("", "", "", "", "", "", 0, nil, nil, nil)

	if config.Issuer != "" {
		t.Error("Empty string should be preserved")
	}
	if config.JWTSecret != "" {
		t.Error("Empty string should be preserved")
	}
	if config.JWTExpiry != "" {
		t.Error("Empty string should be preserved")
	}
	if config.RedisAddr != "" {
		t.Error("Empty string should be preserved")
	}
	if config.RedisPwd != "" {
		t.Error("Empty string should be preserved")
	}
	if config.RedisDB != 0 {
		t.Error("Zero value should be preserved")
	}
	// TTLs should have default values when nil
	if config.RefreshTokenTTL == nil || *config.RefreshTokenTTL != "1h" {
		t.Error("RefreshTokenTTL should have default value")
	}
	if config.PasswordResetTTL == nil || *config.PasswordResetTTL != "10m" {
		t.Error("PasswordResetTTL should have default value")
	}
}

// Utility function to create a pointer to a string
func stringPtr(s string) *string {
	return &s
}
