package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	libRefreshToken "github.com/bcetienne/tools-go-token/lib/refresh-token"
	"github.com/bcetienne/tools-go-token/model"
)

const (
	tokenMaxLength int    = 255
	serviceEnum    string = "REFRESH_TOKEN"
	schema         string = "go_auth"
	table          string = "refresh_token"
)

type RefreshTokenService struct {
	db           *sql.DB
	config       *libRefreshToken.Config
	queryBuilder *lib.QueryBuilder
}

func isIncomingTokenValid(token string) error {
	if len(token) == 0 {
		return errors.New("empty token")
	}
	if len(token) > tokenMaxLength {
		return errors.New("token too long")
	}
	return nil
}

func NewRefreshTokenService(ctx context.Context, db *sql.DB, config *libRefreshToken.Config) (*RefreshTokenService, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	service := &RefreshTokenService{db, config, lib.NewQueryBuilder(schema, table, serviceEnum)}

	// Prepare transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Create schema if not exists
	_, err = tx.ExecContext(ctx, service.queryBuilder.CreateSchemaIfNotExists())
	if err != nil {
		return nil, err
	}

	// Create enum if not exists
	_, err = tx.ExecContext(ctx, service.queryBuilder.CreateEnumIfNotExists())
	if err != nil {
		return nil, err
	}

	var enumValueExists bool
	if err = tx.QueryRowContext(ctx, service.queryBuilder.EnumValueExists()).Scan(&enumValueExists); err != nil {
		return nil, err
	}
	if !enumValueExists {
		_, err = tx.ExecContext(ctx, service.queryBuilder.AddEnum())
		if err != nil {
			return nil, err
		}
	}

	// Create table if not exists
	_, err = tx.ExecContext(ctx, service.queryBuilder.CreateTableIfNotExists())
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return service, nil
}

func (rts *RefreshTokenService) CreateRefreshToken(ctx context.Context, userID int) (*model.Token, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Parse duration from configuration
	duration, err := time.ParseDuration(rts.config.RefreshTokenExpiry)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(duration)

	// Create a random token
	token, err := lib.GenerateRandomString(tokenMaxLength)
	if err != nil {
		return nil, err
	}

	rt := model.NewToken(userID, token, "REFRESH_TOKEN", expiresAt)

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err = tx.QueryRowContext(ctx, rts.queryBuilder.CreateToken(), rt.UserID, rt.TokenValue, rt.ExpiresAt).Scan(&rt.TokenID); err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return rt, nil
}

func (rts *RefreshTokenService) VerifyRefreshToken(ctx context.Context, token string) (*bool, error) {
	if err := isIncomingTokenValid(token); err != nil {
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var exists bool
	if err = tx.QueryRowContext(ctx, rts.queryBuilder.VerifyToken(), token).Scan(&exists); err != nil {
		return nil, err
	}

	return &exists, nil
}

func (rts *RefreshTokenService) RevokeRefreshToken(ctx context.Context, token string, userID int) error {
	if err := isIncomingTokenValid(token); err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, rts.queryBuilder.RevokeToken(), userID, token)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("token not found or already revoked")
	}

	return tx.Commit()
}

func (rts *RefreshTokenService) RevokeAllUserRefreshTokens(ctx context.Context, userID int) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, rts.queryBuilder.RevokeAllUsersTokens(), userID)
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (rts *RefreshTokenService) DeleteExpiredRefreshTokens(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, rts.queryBuilder.FlushExpiredTokens())
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (rts *RefreshTokenService) FlushRefreshTokens(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, rts.queryBuilder.FlushAllTokens())
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (rts *RefreshTokenService) FlushUserRefreshTokens(ctx context.Context, userID int) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := rts.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, rts.queryBuilder.FlushUserTokens(), userID)
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}
