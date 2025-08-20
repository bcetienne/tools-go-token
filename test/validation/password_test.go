package validation

import (
	"testing"

	"github.com/bcetienne/tools-go-token/validation"
)

func Test_Validation_Password_Lowercase(t *testing.T) {
	t.Run("Success - Unit test: Password contains lowercase", func(t *testing.T) {
		password := "passwordContainL0wercase!"
		passwordValidation := validation.NewPasswordValidation()
		if passwordValidation.PasswordContainsLowercase(password) != true {
			t.Fatalf("Password %s does not contains lowercase !", password)
		}
	})
}

func Test_Validation_Password_Uppercase(t *testing.T) {
	t.Run("Success - Unit test: Password contains uppercase", func(t *testing.T) {
		password := "passwordContainUppercas3!"
		passwordValidation := validation.NewPasswordValidation()
		if passwordValidation.PasswordContainsUppercase(password) != true {
			t.Fatalf("Password %s does not contains uppercase !", password)
		}
	})
}

func Test_Validation_Password_Digit(t *testing.T) {
	t.Run("Success - Unit test: Password contains digit", func(t *testing.T) {
		password := "passwordContainD1g1t!"
		passwordValidation := validation.NewPasswordValidation()
		if passwordValidation.PasswordContainsDigit(password) != true {
			t.Fatalf("Password %s does not contains digit !", password)
		}
	})
}

func Test_Validation_Password_SpecialChar(t *testing.T) {
	t.Run("Success - Unit test: Password contains special character", func(t *testing.T) {
		password := "passwordContainSpecial_Char!"
		passwordValidation := validation.NewPasswordValidation()
		if passwordValidation.PasswordContainsSpecialChar(password) != true {
			t.Fatalf("Password %s does not contains special character !", password)
		}
	})
}

func Test_Validation_Password_Length_Equal(t *testing.T) {
	t.Run("Success - Unit test: Password is length of 8", func(t *testing.T) {
		password := "Pass_l08"
		passwordValidation := validation.NewPasswordValidation() // Default length configuration
		if passwordValidation.PasswordHasMinLength(password) != true {
			t.Fatalf("Password %s is too short !", password)
		}
	})
}

func Test_Validation_Password_Length_Higher(t *testing.T) {
	t.Run("Success - Unit test: Password is length of 12", func(t *testing.T) {
		password := "Pass_length13"
		length := 12
		passwordValidation := validation.NewPasswordValidation() // Replace length configuration
		passwordValidation.SetMinLength(length)
		if passwordValidation.PasswordHasMinLength(password) != true {
			t.Fatalf("Password %s is not higher or equal than %d !", password, length)
		}
	})
}

func Test_Validation_Password_Length_TooSmall(t *testing.T) {
	t.Run("Fail - Unit test: Password length configuration cannot be lower than 8", func(t *testing.T) {
		password := "01"
		passwordValidation := validation.NewPasswordValidation() // Replace length configuration
		passwordValidation.SetMinLength(3)
		if passwordValidation.PasswordHasMinLength(password) == true {
			t.Fatalf("Password %s is too short !", password)
		}
	})
}

func Test_Validation_Password_UnauthorizedWords(t *testing.T) {
	t.Run("Fail - Unit test: Use unauthorized word", func(t *testing.T) {
		password := "Lolita"
		passwordValidation := validation.NewPasswordValidation()
		passwordValidation.SetUnauthorizedWords([]string{"Emma", "Lolita"})
		if passwordValidation.PasswordContainsUnauthorizedWord(password) != true {
			t.Fatalf("Password %s contains an unauthorized word !", password)
		}
	})
}

func Test_Validation_Password_TableDriven(t *testing.T) {
	tests := []struct {
		testName          string
		expectSuccess     bool
		password          string
		minLength         int
		unauthorizedWords []string
	}{
		{
			testName:      "Success",
			expectSuccess: true,
			password:      "Er0utibl@nc",
		},
		{
			testName:      "Fail: Cannot set min length lower than 8",
			expectSuccess: false,
			password:      "8TCYZ@i", // length of 7. It should fail, because the default length of 8 should be used
			minLength:     3,
		},
		{
			testName:      "Fail: Too short after length increased",
			expectSuccess: false,
			password:      "SHU4@^pIeJ%k3V3^TV8B", // length of 20
			minLength:     23,
		},
		{
			testName:      "Fail: No uppercase",
			expectSuccess: false,
			password:      "n0upper_cases",
		},
		{
			testName:      "Fail: No lowercase",
			expectSuccess: false,
			password:      "N0_L0WER_CAS&-",
		},
		{
			testName:      "Fail: No special char",
			expectSuccess: false,
			password:      "thereIsN0Sp3ci4lChars",
		},
		{
			testName:      "Fail: No digit",
			expectSuccess: false,
			password:      "Missing_digits?",
		},
		{
			testName:      "Fail: Too short",
			expectSuccess: false,
			password:      "Tet-1",
		},
		{
			testName:          "Fail: Unauthorized word",
			expectSuccess:     false,
			password:          "FckTh1sSh!t",
			unauthorizedWords: []string{"FckTh1sSh!t"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			passwordValidation := validation.NewPasswordValidation()
			if tt.minLength != 0 {
				passwordValidation.SetMinLength(tt.minLength)
			}
			if len(tt.unauthorizedWords) > 0 {
				passwordValidation.SetUnauthorizedWords(tt.unauthorizedWords)
			}

			validPassword := passwordValidation.IsPasswordStrengthEnough(tt.password)
			if tt.expectSuccess != validPassword {
				t.Fatalf("The password has the valid status (%v), while %v was expected", validPassword, tt.expectSuccess)
			}
		})
	}

}
