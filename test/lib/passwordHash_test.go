package lib

import (
	"testing"

	"github.com/bcetienne/tools-go-token/lib"
)

func Test_Lib_PasswordHash_Hash(t *testing.T) {
	t.Run("Success: Hash password", func(t *testing.T) {
		passwordHash := lib.NewPasswordHash()
		hash, err := passwordHash.Hash("SecurePassw0rd!")
		if err != nil {
			t.Fatalf("Hash trigger an error %v", err)
		}
		if len(hash) == 0 {
			t.Fatalf("Hash password is empty")
		}
	})
}

func Test_Lib_PasswordHash_Hash_EmptyString(t *testing.T) {
	t.Run("Fail: Hash password - Empty string", func(t *testing.T) {
		passwordHash := lib.NewPasswordHash()
		hash, err := passwordHash.Hash("")
		if err == nil || len(hash) > 0 {
			t.Fatal("Hash should not be generated with empty string !")
		}
	})
}

func Test_Lib_PasswordHash_CheckHash_Success(t *testing.T) {
	t.Run("Success: Check hash password", func(t *testing.T) {
		password := "SecurePassw0rd!"
		passwordHash := lib.NewPasswordHash()
		hash, err := passwordHash.Hash(password)
		if err != nil {
			t.Fatalf("Hash trigger an error %v", err)
		}
		if len(hash) == 0 {
			t.Fatalf("Hash password is empty")
		}
		if passwordHash.CheckHash(password, hash) != true {
			t.Fatalf("Hash %s does not belong to this password %s !", hash, password)
		}
	})
}

func Test_Lib_PasswordHash_CheckHash_Fail(t *testing.T) {
	t.Run("Fail: Check hash with bad password", func(t *testing.T) {
		password := "SecurePassw0rd!"
		passwordHash := lib.NewPasswordHash()
		hash, err := passwordHash.Hash(password)
		if err != nil {
			t.Fatalf("Hash trigger an error %v", err)
		}
		if len(hash) == 0 {
			t.Fatalf("Hash password is empty")
		}
		password = "BadPassw0rd!"
		if passwordHash.CheckHash(password, hash) != false {
			t.Fatalf("Hash %s does not belong to this password %s !", hash, password)
		}
	})
}

func Test_Lib_PasswordHash_CheckHash_Fail_InvalidHash(t *testing.T) {
	t.Run("Fail: Check hash with invalid hash", func(t *testing.T) {
		password := "SecurePassw0rd!"
		passwordHash := lib.NewPasswordHash()
		hash, err := passwordHash.Hash(password)
		if err != nil {
			t.Fatalf("Hash trigger an error %v", err)
		}
		if len(hash) == 0 {
			t.Fatalf("Hash password is empty")
		}
		hash = "baadHash"
		if passwordHash.CheckHash(password, hash) != false {
			t.Fatalf("Hash %s does not belong to this password %s !", hash, password)
		}
	})
}

func Test_Lib_PasswordHash_CheckHash_Fail_EmptyHash(t *testing.T) {
	t.Run("Fail: Check hash with empty hash", func(t *testing.T) {
		password := "SecurePassw0rd!"
		passwordHash := lib.NewPasswordHash()
		hash, err := passwordHash.Hash(password)
		if err != nil {
			t.Fatalf("Hash trigger an error %v", err)
		}
		if len(hash) == 0 {
			t.Fatalf("Hash password is empty")
		}
		hash = ""
		if passwordHash.CheckHash(password, hash) != false {
			t.Fatalf("Hash %s does not belong to this password %s !", hash, password)
		}
	})
}

func Test_Lib_PasswordHash_CheckHash_Fail_EmptyPassword(t *testing.T) {
	t.Run("Fail: Check hash with empty password", func(t *testing.T) {
		password := "SecurePassw0rd!"
		passwordHash := lib.NewPasswordHash()
		hash, err := passwordHash.Hash(password)
		if err != nil {
			t.Fatalf("Hash trigger an error %v", err)
		}
		if len(hash) == 0 {
			t.Fatalf("Hash password is empty")
		}
		password = ""
		if passwordHash.CheckHash(password, hash) != false {
			t.Fatalf("Hash %s does not belong to this password %s !", hash, password)
		}
	})
}
