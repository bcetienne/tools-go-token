package refresh_token

import (
	"testing"

	configRefreshToken "github.com/bcetienne/tools-go-token/lib/refresh-token"
)

func Test_NewConfig_Success(t *testing.T) {
	// Arrange
	issuer := "test-issuer"
	jwtSecret := "super-secret-key"
	jwtExpiry := "15m"
	refreshTokenExpiry := "24h"

	// Act
	config := configRefreshToken.NewConfig(issuer, jwtSecret, jwtExpiry, refreshTokenExpiry)

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

	if config.RefreshTokenExpiry != refreshTokenExpiry {
		t.Fatalf("Expected RefreshTokenExpiry to be %s, got %s", refreshTokenExpiry, config.RefreshTokenExpiry)
	}
}

func Test_NewConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name               string
		issuer             string
		jwtSecret          string
		jwtExpiry          string
		refreshTokenExpiry string
		expectValid        bool
	}{
		{
			name:               "Valid config with standard values",
			issuer:             "my-app",
			jwtSecret:          "my-jwt-secret-key",
			jwtExpiry:          "15m",
			refreshTokenExpiry: "7d",
			expectValid:        true,
		},
		{
			name:               "Valid config with empty values",
			issuer:             "",
			jwtSecret:          "",
			jwtExpiry:          "",
			refreshTokenExpiry: "",
			expectValid:        true, // Le constructeur accepte tout
		},
		{
			name:               "Valid config with special characters",
			issuer:             "app-test@domain.com",
			jwtSecret:          "secret!@#$%^&*()",
			jwtExpiry:          "30m",
			refreshTokenExpiry: "30d",
			expectValid:        true,
		},
		{
			name:               "Valid config with long values",
			issuer:             "very-long-issuer-name-for-testing-purposes",
			jwtSecret:          "very-long-jwt-secret-key-with-many-characters-for-security",
			jwtExpiry:          "1h",
			refreshTokenExpiry: "720h",
			expectValid:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			config := configRefreshToken.NewConfig(tt.issuer, tt.jwtSecret, tt.jwtExpiry, tt.refreshTokenExpiry)

			// Assert
			if !tt.expectValid {
				if config != nil {
					t.Fatal("Expected NewConfig to return nil for invalid input")
				}
				return
			}

			if config == nil {
				t.Fatal("NewConfig should return a non-nil Config")
			}

			// Vérifier que tous les champs sont correctement assignés
			if config.Issuer != tt.issuer {
				t.Fatalf("Expected Issuer to be %q, got %q", tt.issuer, config.Issuer)
			}

			if config.JWTSecret != tt.jwtSecret {
				t.Fatalf("Expected JWTSecret to be %q, got %q", tt.jwtSecret, config.JWTSecret)
			}

			if config.JWTExpiry != tt.jwtExpiry {
				t.Fatalf("Expected JWTExpiry to be %q, got %q", tt.jwtExpiry, config.JWTExpiry)
			}

			if config.RefreshTokenExpiry != tt.refreshTokenExpiry {
				t.Fatalf("Expected RefreshTokenExpiry to be %q, got %q", tt.refreshTokenExpiry, config.RefreshTokenExpiry)
			}
		})
	}
}

func Test_Config_StructFields(t *testing.T) {
	// Test que la structure Config a les bons champs
	config := &configRefreshToken.Config{
		Issuer:             "test-issuer",
		JWTSecret:          "test-secret",
		JWTExpiry:          "15m",
		RefreshTokenExpiry: "24h",
	}

	// Vérifier que tous les champs sont accessibles
	if config.Issuer == "" {
		t.Error("Issuer field should be accessible")
	}
	if config.JWTSecret == "" {
		t.Error("JWTSecret field should be accessible")
	}
	if config.JWTExpiry == "" {
		t.Error("JWTExpiry field should be accessible")
	}
	if config.RefreshTokenExpiry == "" {
		t.Error("RefreshTokenExpiry field should be accessible")
	}
}

func Test_Config_Modification(t *testing.T) {
	// Test que les champs peuvent être modifiés après création
	config := configRefreshToken.NewConfig("original", "original", "original", "original")

	// Modifier les valeurs
	config.Issuer = "modified"
	config.JWTSecret = "modified"
	config.JWTExpiry = "modified"
	config.RefreshTokenExpiry = "modified"

	// Vérifier les modifications
	if config.Issuer != "modified" {
		t.Error("Issuer should be modifiable")
	}
	if config.JWTSecret != "modified" {
		t.Error("JWTSecret should be modifiable")
	}
	if config.JWTExpiry != "modified" {
		t.Error("JWTExpiry should be modifiable")
	}
	if config.RefreshTokenExpiry != "modified" {
		t.Error("RefreshTokenExpiry should be modifiable")
	}
}
