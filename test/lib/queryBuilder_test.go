package lib

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bcetienne/tools-go-token/lib"
)

func Test_NewQueryBuilder(t *testing.T) {
	t.Run("Success - QueryBuilder creation", func(t *testing.T) {
		qb := lib.NewQueryBuilder("auth", "test_tokens", "REFRESH_TOKEN")
		if qb == nil {
			t.Fatal("QueryBuilder should not be nil")
		}
	})
}

func Test_QueryBuilderCreateSchemaIfNotExists(t *testing.T) {
	schema := "auth"
	qb := lib.NewQueryBuilder(schema, "test_tokens", "REFRESH_TOKEN")
	query := qb.CreateSchemaIfNotExists()
	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if query != fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema) {
		t.Fatalf("Query has wrong schema (%s): %s", schema, query)
	}
}

func Test_QueryBuilderCreateTableIfNotExists(t *testing.T) {
	schema := "auto"
	table := "imaginary"
	qb := lib.NewQueryBuilder(schema, table, "REFRESH_TOKEN")
	query := qb.CreateTableIfNotExists()
	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.%s", schema, table)) {
		t.Fatalf("Query has wrong table (%s.%s): %s", schema, table, query)
	}
}

func Test_QueryBuilderEnumValueExists(t *testing.T) {
	schema := "auth"
	tokenType := "ACCESS_TOKEN"
	qb := lib.NewQueryBuilder(schema, "test_tokens", tokenType)
	query := qb.EnumValueExists()

	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("WHERE n.nspname = '%s'", schema)) {
		t.Fatalf("Query should contain schema name (%s): %s", schema, query)
	}
	if !strings.Contains(query, fmt.Sprintf("AND e.enumlabel = '%s'", tokenType)) {
		t.Fatalf("Query should contain token type (%s): %s", tokenType, query)
	}
}

func Test_QueryBuilderCreateEnumIfNotExists(t *testing.T) {
	schema := "auth"
	qb := lib.NewQueryBuilder(schema, "test_tokens", "REFRESH_TOKEN")
	query := qb.CreateEnumIfNotExists()

	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("WHERE n.nspname = '%s'", schema)) {
		t.Fatalf("Query should contain schema name (%s): %s", schema, query)
	}
	if !strings.Contains(query, fmt.Sprintf("CREATE TYPE %s.token_type AS ENUM", schema)) {
		t.Fatalf("Query should create enum type in schema (%s): %s", schema, query)
	}
}

func Test_QueryBuilderAddEnum(t *testing.T) {
	schema := "auth"
	tokenType := "API_TOKEN"
	qb := lib.NewQueryBuilder(schema, "test_tokens", tokenType)
	query := qb.AddEnum()

	expected := fmt.Sprintf("ALTER TYPE %s.token_type ADD VALUE '%s'", schema, tokenType)
	if query != expected {
		t.Fatalf("Expected: %s, Got: %s", expected, query)
	}
}

func Test_QueryBuilderCreateToken(t *testing.T) {
	schema := "auth"
	table := "tokens"
	tokenType := "RESET_TOKEN"
	qb := lib.NewQueryBuilder(schema, table, tokenType)
	query := qb.CreateToken()

	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("INSERT INTO %s.%s", schema, table)) {
		t.Fatalf("Query should insert into correct table (%s.%s): %s", schema, table, query)
	}
	if !strings.Contains(query, fmt.Sprintf("VALUES ($1, '%s', $2, $3)", tokenType)) {
		t.Fatalf("Query should contain token type (%s): %s", tokenType, query)
	}
	if !strings.Contains(query, "RETURNING token_id") {
		t.Fatalf("Query should return token_id: %s", query)
	}
}

func Test_QueryBuilderVerifyToken(t *testing.T) {
	schema := "auth"
	table := "tokens"
	tokenType := "EMAIL_VERIFICATION"
	qb := lib.NewQueryBuilder(schema, table, tokenType)
	query := qb.VerifyToken()

	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("FROM %s.%s", schema, table)) {
		t.Fatalf("Query should select from correct table (%s.%s): %s", schema, table, query)
	}
	if !strings.Contains(query, fmt.Sprintf("AND token_type = '%s'", tokenType)) {
		t.Fatalf("Query should filter by token type (%s): %s", tokenType, query)
	}
	if !strings.Contains(query, "AND revoked_at IS NULL") {
		t.Fatalf("Query should check revocation status: %s", query)
	}
	if !strings.Contains(query, "AND expires_at > NOW()") {
		t.Fatalf("Query should check expiration: %s", query)
	}
}

func Test_QueryBuilderRevokeToken(t *testing.T) {
	schema := "auth"
	table := "tokens"
	tokenType := "SESSION_TOKEN"
	qb := lib.NewQueryBuilder(schema, table, tokenType)
	query := qb.RevokeToken()

	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("UPDATE %s.%s", schema, table)) {
		t.Fatalf("Query should update correct table (%s.%s): %s", schema, table, query)
	}
	if !strings.Contains(query, "SET revoked_at = NOW()") {
		t.Fatalf("Query should set revoked_at: %s", query)
	}
	if !strings.Contains(query, fmt.Sprintf("AND token_type = '%s'", tokenType)) {
		t.Fatalf("Query should filter by token type (%s): %s", tokenType, query)
	}
	if !strings.Contains(query, "WHERE user_id = $1 AND token_value = $2") {
		t.Fatalf("Query should use parameterized user_id and token_value: %s", query)
	}
}

func Test_QueryBuilderRevokeAllUsersTokens(t *testing.T) {
	schema := "auth"
	table := "tokens"
	tokenType := "REFRESH_TOKEN"
	qb := lib.NewQueryBuilder(schema, table, tokenType)
	query := qb.RevokeAllUsersTokens()

	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("UPDATE %s.%s", schema, table)) {
		t.Fatalf("Query should update correct table (%s.%s): %s", schema, table, query)
	}
	if !strings.Contains(query, "SET revoked_at = NOW()") {
		t.Fatalf("Query should set revoked_at: %s", query)
	}
	if !strings.Contains(query, "WHERE user_id = $1") {
		t.Fatalf("Query should filter by user_id: %s", query)
	}
	if !strings.Contains(query, fmt.Sprintf("AND token_type = '%s'", tokenType)) {
		t.Fatalf("Query should filter by token type (%s): %s", tokenType, query)
	}
}

func Test_QueryBuilderFlushExpiredTokens(t *testing.T) {
	schema := "auth"
	table := "tokens"
	tokenType := "TEMP_TOKEN"
	qb := lib.NewQueryBuilder(schema, table, tokenType)
	query := qb.FlushExpiredTokens()

	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("DELETE FROM %s.%s", schema, table)) {
		t.Fatalf("Query should delete from correct table (%s.%s): %s", schema, table, query)
	}
	if !strings.Contains(query, fmt.Sprintf("WHERE token_type = '%s'", tokenType)) {
		t.Fatalf("Query should filter by token type (%s): %s", tokenType, query)
	}
	if !strings.Contains(query, "expires_at < NOW()") {
		t.Fatalf("Query should check expiration: %s", query)
	}
	if !strings.Contains(query, "revoked_at IS NOT NULL AND revoked_at < NOW()") {
		t.Fatalf("Query should check revocation: %s", query)
	}
}

func Test_QueryBuilderFlushAllTokens(t *testing.T) {
	schema := "auth"
	table := "tokens"
	tokenType := "ALL_TOKENS"
	qb := lib.NewQueryBuilder(schema, table, tokenType)
	query := qb.FlushAllTokens()

	expected := fmt.Sprintf("DELETE FROM %s.%s WHERE token_type = '%s'", schema, table, tokenType)
	if query != expected {
		t.Fatalf("Expected: %s, Got: %s", expected, query)
	}
}

func Test_QueryBuilderFlushUserTokens(t *testing.T) {
	schema := "auth"
	table := "tokens"
	tokenType := "USER_TOKEN"
	qb := lib.NewQueryBuilder(schema, table, tokenType)
	query := qb.FlushUserTokens()

	if query == "" {
		t.Fatal("Query should not be empty")
	}
	if !strings.Contains(query, fmt.Sprintf("DELETE FROM %s.%s", schema, table)) {
		t.Fatalf("Query should delete from correct table (%s.%s): %s", schema, table, query)
	}
	if !strings.Contains(query, "WHERE user_id = $1") {
		t.Fatalf("Query should filter by user_id: %s", query)
	}
	if !strings.Contains(query, fmt.Sprintf("AND token_type = '%s'", tokenType)) {
		t.Fatalf("Query should filter by token type (%s): %s", tokenType, query)
	}
}

func Test_QueryBuilderTableDriven(t *testing.T) {
	tests := []struct {
		name      string
		schema    string
		table     string
		tokenType string
		method    string
	}{
		{
			name:      "Different schema and table combination 1",
			schema:    "production",
			table:     "user_tokens",
			tokenType: "JWT",
			method:    "CreateSchemaIfNotExists",
		},
		{
			name:      "Different schema and table combination 2",
			schema:    "staging",
			table:     "auth_tokens",
			tokenType: "BEARER",
			method:    "CreateTableIfNotExists",
		},
		{
			name:      "Special characters in names",
			schema:    "test_db",
			table:     "temp_tokens",
			tokenType: "API_KEY",
			method:    "AddEnum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qb := lib.NewQueryBuilder(tt.schema, tt.table, tt.tokenType)
			if qb == nil {
				t.Fatal("QueryBuilder should not be nil")
			}

			switch tt.method {
			case "CreateSchemaIfNotExists":
				query := qb.CreateSchemaIfNotExists()
				if !strings.Contains(query, tt.schema) {
					t.Fatalf("Query should contain schema name: %s", query)
				}
			case "CreateTableIfNotExists":
				query := qb.CreateTableIfNotExists()
				if !strings.Contains(query, fmt.Sprintf("%s.%s", tt.schema, tt.table)) {
					t.Fatalf("Query should contain full table name: %s", query)
				}
			case "AddEnum":
				query := qb.AddEnum()
				if !strings.Contains(query, tt.tokenType) {
					t.Fatalf("Query should contain token type: %s", query)
				}
			}
		})
	}
}
