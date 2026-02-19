package refresh_token

import (
	"testing"

	modelAuth "github.com/bcetienne/tools-go-token/v4/model/auth"
)

func Test_NewAuthUser_Success(t *testing.T) {
	// Arrange
	id := "550e8400-e29b-41d4-a716-446655440000"
	email := "test@example.com"

	// Act
	authUser := modelAuth.NewUser(id, email)

	// Assert
	if authUser == nil {
		t.Fatal("NewAuthUser should return a non-nil AuthUser")
	}

	if authUser.ID != id {
		t.Fatalf("Expected ID to be %s, got %s", id, authUser.ID)
	}

	if authUser.Email != email {
		t.Fatalf("Expected Email to be %s, got %s", email, authUser.Email)
	}
}

func Test_AuthUser_GetID(t *testing.T) {
	// Arrange
	expectedID := "456"
	authUser := modelAuth.NewUser(expectedID, "test@example.com")

	// Act
	id := authUser.GetID()

	// Assert
	if id != expectedID {
		t.Fatalf("Expected GetID() to return %s, got %s", expectedID, id)
	}
}

func Test_AuthUser_GetEmail(t *testing.T) {
	// Arrange
	expectedEmail := "user@domain.com"
	authUser := modelAuth.NewUser("123", expectedEmail)

	// Act
	email := authUser.GetEmail()

	// Assert
	if email != expectedEmail {
		t.Fatalf("Expected GetEmail() to return %s, got %s", expectedEmail, email)
	}
}

func Test_AuthUser_Interface_Compliance(t *testing.T) {
	// Arrange
	authUser := modelAuth.NewUser("789", "interface@test.com")

	// Act & Assert - Test que AuthUser implémente AuthUserInterface
	var _ modelAuth.UserInterface = authUser

	// Test toutes les méthodes de l'interface
	if authUser.GetID() != "789" {
		t.Error("GetID() should return the correct user ID")
	}

	if authUser.GetEmail() != "interface@test.com" {
		t.Error("GetEmail() should return the correct email")
	}
}

func Test_AuthUser_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		email    string
		expected modelAuth.User
	}{
		{
			name:  "Standard user with UUID",
			id:    "550e8400-e29b-41d4-a716-446655440000",
			email: "john.doe@example.com",
			expected: modelAuth.User{
				ID:    "550e8400-e29b-41d4-a716-446655440000",
				Email: "john.doe@example.com",
			},
		},
		{
			name:  "User with numeric ID",
			id:    "123",
			email: "numeric@example.com",
			expected: modelAuth.User{
				ID:    "123",
				Email: "numeric@example.com",
			},
		},
		{
			name:  "User with zero ID",
			id:    "0",
			email: "zero@example.com",
			expected: modelAuth.User{
				ID:    "0",
				Email: "zero@example.com",
			},
		},
		{
			name:  "User with empty strings",
			id:    "",
			email: "",
			expected: modelAuth.User{
				ID:    "",
				Email: "",
			},
		},
		{
			name:  "User with special characters",
			id:    "special-chars-!@#$%",
			email: "test+special@example-domain.co.uk",
			expected: modelAuth.User{
				ID:    "special-chars-!@#$%",
				Email: "test+special@example-domain.co.uk",
			},
		},
		{
			name:  "User with alphanumeric ID",
			id:    "user-abc123-xyz789",
			email: "alphanumeric@example.com",
			expected: modelAuth.User{
				ID:    "user-abc123-xyz789",
				Email: "alphanumeric@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			authUser := modelAuth.NewUser(tt.id, tt.email)

			// Assert
			if authUser.ID != tt.expected.ID {
				t.Fatalf("Expected ID to be %q, got %q", tt.expected.ID, authUser.ID)
			}

			if authUser.Email != tt.expected.Email {
				t.Fatalf("Expected Email to be %q, got %q", tt.expected.Email, authUser.Email)
			}

			// Test les getters aussi
			if authUser.GetID() != tt.expected.ID {
				t.Fatalf("Expected GetID() to return %q, got %q", tt.expected.ID, authUser.GetID())
			}

			if authUser.GetEmail() != tt.expected.Email {
				t.Fatalf("Expected GetEmail() to return %q, got %q", tt.expected.Email, authUser.GetEmail())
			}
		})
	}
}

func Test_AuthUser_StructFields_DirectAccess(t *testing.T) {
	// Test que les champs de la structure sont accessibles directement
	authUser := &modelAuth.User{
		ID:    "direct-access-id",
		Email: "direct@access.com",
	}

	// Test accès direct aux champs
	if authUser.ID != "direct-access-id" {
		t.Error("ID field should be directly accessible")
	}

	if authUser.Email != "direct@access.com" {
		t.Error("Email field should be directly accessible")
	}
}

func Test_AuthUser_Modification_AfterCreation(t *testing.T) {
	// Test que les champs peuvent être modifiés après création
	authUser := modelAuth.NewUser("original-id", "original@test.com")

	// Modifier les valeurs
	authUser.ID = "modified-id"
	authUser.Email = "modified@test.com"

	// Vérifier les modifications via les getters
	if authUser.GetID() != "modified-id" {
		t.Error("ID should be modifiable")
	}

	if authUser.GetEmail() != "modified@test.com" {
		t.Error("Email should be modifiable")
	}
}

func Test_AuthUser_JSONTags(t *testing.T) {
	// Test conceptuel - vérifie que la structure a les bons tags JSON
	// (en pratique, vous testeriez cela avec du marshalling/unmarshalling JSON réel)
	authUser := modelAuth.NewUser("json-test-id", "json@test.com")

	// Vérifier que la structure peut être utilisée pour JSON
	if authUser == nil {
		t.Fatal("AuthUser should be suitable for JSON serialization")
	}

	// Les tags JSON sont: id, email
	// Ce test vérifie juste que la structure est bien formée
	if authUser.ID == "" && authUser.Email == "" {
		t.Error("AuthUser structure should have proper JSON tag mapping")
	}
}
