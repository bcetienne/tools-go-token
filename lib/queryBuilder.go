package lib

import "fmt"

type QueryBuilder struct {
	schemaName string
	tableName  string
	tokenType  string
}

var schemaTable string

func NewQueryBuilder(schemaName, tableName, tokenType string) *QueryBuilder {
	schemaTable = fmt.Sprintf("%s.%s", schemaName, tableName)
	return &QueryBuilder{schemaName, tableName, tokenType}
}

func (qb *QueryBuilder) CreateSchemaIfNotExists() string {
	return fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, qb.schemaName)
}

func (qb *QueryBuilder) CreateTableIfNotExists() string {
	return fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
		    token_id SERIAL PRIMARY KEY,
		    user_id INT NOT NULL,
		    token_type %s.token_type NOT NULL,
		    token_value VARCHAR NOT NULL,
		    expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at TIMESTAMPTZ,
			UNIQUE(token_value, token_type)
		);
		CREATE INDEX IF NOT EXISTS idx_token_user_id ON %s(user_id);
		CREATE INDEX IF NOT EXISTS idx_token_token_value ON %s(token_value);
		CREATE INDEX IF NOT EXISTS idx_token_expires_at ON %s(expires_at);
		`,
		schemaTable,
		qb.schemaName,
		schemaTable,
		schemaTable,
		schemaTable,
	)
}

func (qb *QueryBuilder) EnumValueExists() string {
	return fmt.Sprintf(`
        SELECT EXISTS (
            SELECT 1 
            FROM pg_enum e
            JOIN pg_type t ON e.enumtypid = t.oid
            JOIN pg_namespace n ON t.typnamespace = n.oid
            WHERE n.nspname = '%s'
            AND t.typname = 'token_type'
            AND e.enumlabel = '%s'
        )
    `, qb.schemaName, qb.tokenType)
}

func (qb *QueryBuilder) CreateEnumIfNotExists() string {
	return fmt.Sprintf(`
        DO $$ 
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON t.typnamespace = n.oid WHERE n.nspname = '%s' AND t.typname = 'token_type' AND t.typtype = 'e') THEN
                CREATE TYPE %s.token_type AS ENUM ();
            END IF;
        END$$;
    `, qb.schemaName, qb.schemaName)
}

func (qb *QueryBuilder) AddEnum() string {
	return fmt.Sprintf(`ALTER TYPE %s.token_type ADD VALUE '%s'`, qb.schemaName, qb.tokenType)
}

func (qb *QueryBuilder) CreateToken() string {
	return fmt.Sprintf(`
		INSERT INTO %s (user_id, token_type, token_value, expires_at) 
			VALUES ($1, '%s', $2, $3) 
			RETURNING token_id
	`, schemaTable, qb.tokenType)
}

func (qb *QueryBuilder) VerifyToken() string {
	return fmt.Sprintf(`SELECT EXISTS(SELECT token_id FROM %s WHERE token_value = $1 AND token_type = '%s' AND revoked_at IS NULL AND expires_at > NOW())`, schemaTable, qb.tokenType)
}

func (qb *QueryBuilder) RevokeToken() string {
	return fmt.Sprintf(`UPDATE %s SET revoked_at = NOW() WHERE user_id = $1 AND token_value = $2 AND token_type = '%s' AND revoked_at IS NULL`, schemaTable, qb.tokenType)
}

func (qb *QueryBuilder) RevokeAllUsersTokens() string {
	return fmt.Sprintf(`UPDATE %s SET revoked_at = NOW() WHERE user_id = $1 AND token_type = '%s' AND revoked_at IS NULL`, schemaTable, qb.tokenType)
}

func (qb *QueryBuilder) FlushExpiredTokens() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE token_type = '%s' AND expires_at < NOW() OR (revoked_at IS NOT NULL AND revoked_at < NOW())`, schemaTable, qb.tokenType)
}

func (qb *QueryBuilder) FlushAllTokens() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE token_type = '%s'`, schemaTable, qb.tokenType)
}

func (qb *QueryBuilder) FlushUserTokens() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE user_id = $1 AND token_type = '%s'`, schemaTable, qb.tokenType)
}
