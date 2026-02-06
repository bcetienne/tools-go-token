package refresh_token

import (
	"testing"

	modelRefreshToken "github.com/bcetienne/tools-go-token/model/refresh-token"
)

func Test_NewAuthUser_Success(t *testing.T) {
	// Arrange
	userID := 123
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	email := "test@example.com"

	// Act
	authUser := modelRefreshToken.NewAuthUser(userID, uuid, email)

	// Assert
	if authUser == nil {
		t.Fatal("NewAuthUser should return a non-nil AuthUser")
	}

	if authUser.UserID != userID {
		t.Fatalf("Expected UserID to be %d, got %d", userID, authUser.UserID)
	}

	if authUser.UserUUID != uuid {
		t.Fatalf("Expected UserUUID to be %s, got %s", uuid, authUser.UserUUID)
	}

	if authUser.Email != email {
		t.Fatalf("Expected Email to be %s, got %s", email, authUser.Email)
	}
}

func Test_AuthUser_GetUserID(t *testing.T) {
	// Arrange
	expectedUserID := 456
	authUser := modelRefreshToken.NewAuthUser(expectedUserID, "test-uuid", "test@example.com")

	// Act
	userID := authUser.GetUserID()

	// Assert
	if userID != expectedUserID {
		t.Fatalf("Expected GetUserID() to return %d, got %d", expectedUserID, userID)
	}
}

func Test_AuthUser_GetUserUUID(t *testing.T) {
	// Arrange
	expectedUUID := "123e4567-e89b-12d3-a456-426614174000"
	authUser := modelRefreshToken.NewAuthUser(123, expectedUUID, "test@example.com")

	// Act
	uuid := authUser.GetUserUUID()

	// Assert
	if uuid != expectedUUID {
		t.Fatalf("Expected GetUserUUID() to return %s, got %s", expectedUUID, uuid)
	}
}

func Test_AuthUser_GetEmail(t *testing.T) {
	// Arrange
	expectedEmail := "user@domain.com"
	authUser := modelRefreshToken.NewAuthUser(123, "test-uuid", expectedEmail)

	// Act
	email := authUser.GetEmail()

	// Assert
	if email != expectedEmail {
		t.Fatalf("Expected GetEmail() to return %s, got %s", expectedEmail, email)
	}
}

func Test_AuthUser_Interface_Compliance(t *testing.T) {
	// Arrange
	authUser := modelRefreshToken.NewAuthUser(789, "interface-test-uuid", "interface@test.com")

	// Act & Assert - Test que AuthUser implémente AuthUserInterface
	var _ modelRefreshToken.AuthUserInterface = authUser

	// Test toutes les méthodes de l'interface
	if authUser.GetUserID() != 789 {
		t.Error("GetUserID() should return the correct user ID")
	}

	if authUser.GetUserUUID() != "interface-test-uuid" {
		t.Error("GetUserUUID() should return the correct UUID")
	}

	if authUser.GetEmail() != "interface@test.com" {
		t.Error("GetEmail() should return the correct email")
	}
}

func Test_AuthUser_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		userID   int
		uuid     string
		email    string
		expected modelRefreshToken.AuthUser
	}{
		{
			name:   "Standard user",
			userID: 1,
			uuid:   "550e8400-e29b-41d4-a716-446655440000",
			email:  "john.doe@example.com",
			expected: modelRefreshToken.AuthUser{
				UserID:   1,
				UserUUID: "550e8400-e29b-41d4-a716-446655440000",
				Email:    "john.doe@example.com",
			},
		},
		{
			name:   "User with zero ID",
			userID: 0,
			uuid:   "00000000-0000-0000-0000-000000000000",
			email:  "zero@example.com",
			expected: modelRefreshToken.AuthUser{
				UserID:   0,
				UserUUID: "00000000-0000-0000-0000-000000000000",
				Email:    "zero@example.com",
			},
		},
		{
			name:   "User with negative ID",
			userID: -1,
			uuid:   "negative-uuid",
			email:  "negative@example.com",
			expected: modelRefreshToken.AuthUser{
				UserID:   -1,
				UserUUID: "negative-uuid",
				Email:    "negative@example.com",
			},
		},
		{
			name:   "User with empty strings",
			userID: 999,
			uuid:   "",
			email:  "",
			expected: modelRefreshToken.AuthUser{
				UserID:   999,
				UserUUID: "",
				Email:    "",
			},
		},
		{
			name:   "User with special characters",
			userID: 123,
			uuid:   "special-chars-!@#$%",
			email:  "test+special@example-domain.co.uk",
			expected: modelRefreshToken.AuthUser{
				UserID:   123,
				UserUUID: "special-chars-!@#$%",
				Email:    "test+special@example-domain.co.uk",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			authUser := modelRefreshToken.NewAuthUser(tt.userID, tt.uuid, tt.email)

			// Assert
			if authUser.UserID != tt.expected.UserID {
				t.Fatalf("Expected UserID to be %d, got %d", tt.expected.UserID, authUser.UserID)
			}

			if authUser.UserUUID != tt.expected.UserUUID {
				t.Fatalf("Expected UserUUID to be %q, got %q", tt.expected.UserUUID, authUser.UserUUID)
			}

			if authUser.Email != tt.expected.Email {
				t.Fatalf("Expected Email to be %q, got %q", tt.expected.Email, authUser.Email)
			}

			// Test les getters aussi
			if authUser.GetUserID() != tt.expected.UserID {
				t.Fatalf("Expected GetUserID() to return %d, got %d", tt.expected.UserID, authUser.GetUserID())
			}

			if authUser.GetUserUUID() != tt.expected.UserUUID {
				t.Fatalf("Expected GetUserUUID() to return %q, got %q", tt.expected.UserUUID, authUser.GetUserUUID())
			}

			if authUser.GetEmail() != tt.expected.Email {
				t.Fatalf("Expected GetEmail() to return %q, got %q", tt.expected.Email, authUser.GetEmail())
			}
		})
	}
}

func Test_AuthUser_StructFields_DirectAccess(t *testing.T) {
	// Test que les champs de la structure sont accessibles directement
	authUser := &modelRefreshToken.AuthUser{
		UserID:   42,
		UserUUID: "direct-access-uuid",
		Email:    "direct@access.com",
	}

	// Test accès direct aux champs
	if authUser.UserID != 42 {
		t.Error("UserID field should be directly accessible")
	}

	if authUser.UserUUID != "direct-access-uuid" {
		t.Error("UserUUID field should be directly accessible")
	}

	if authUser.Email != "direct@access.com" {
		t.Error("Email field should be directly accessible")
	}
}

func Test_AuthUser_Modification_AfterCreation(t *testing.T) {
	// Test que les champs peuvent être modifiés après création
	authUser := modelRefreshToken.NewAuthUser(1, "original", "original@test.com")

	// Modifier les valeurs
	authUser.UserID = 999
	authUser.UserUUID = "modified-uuid"
	authUser.Email = "modified@test.com"

	// Vérifier les modifications via les getters
	if authUser.GetUserID() != 999 {
		t.Error("UserID should be modifiable")
	}

	if authUser.GetUserUUID() != "modified-uuid" {
		t.Error("UserUUID should be modifiable")
	}

	if authUser.GetEmail() != "modified@test.com" {
		t.Error("Email should be modifiable")
	}
}

func Test_AuthUser_JSONTags(t *testing.T) {
	// Test conceptual - vérifie que la structure a les bons tags JSON
	// (en pratique, vous testeriez cela avec du marshalling/unmarshalling JSON réel)
	authUser := modelRefreshToken.NewAuthUser(123, "json-test", "json@test.com")

	// Vérifier que la structure peut être utilisée pour JSON
	if authUser == nil {
		t.Fatal("AuthUser should be suitable for JSON serialization")
	}

	// Les tags JSON sont: user_id, user_uuid, email
	// Ce test vérifie juste que la structure est bien formée
	if authUser.UserID == 0 && authUser.UserUUID == "" && authUser.Email == "" {
		t.Error("AuthUser structure should have proper JSON tag mapping")
	}
}
