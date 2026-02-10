package validation

import (
	"testing"

	"github.com/bcetienne/tools-go-token/v4/validation"
)

func Test_Validation_Email_TableDriven(t *testing.T) {
	tests := []struct {
		testName      string
		expectSuccess bool
		email         string
	}{
		{
			testName:      "Success",
			expectSuccess: true,
			email:         "gardena19@mail.com",
		},
		{
			testName:      "Fail: Empty",
			expectSuccess: false,
			email:         "",
		},
		{
			testName:      "Fail: Wrong format",
			expectSuccess: false,
			email:         "b!ad@form()t.com",
		},
	}

	// Instantiate the email validation struct once before tests
	emailValidation := validation.NewEmailValidation()

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			validEmail := emailValidation.IsValidEmail(tt.email)
			if tt.expectSuccess != validEmail {
				t.Fatalf("The email has the valid status (%v), while %v was expected", validEmail, tt.expectSuccess)
			}
		})
	}
}
