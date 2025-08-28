package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/bcetienne/tools-go-token/model"
	"github.com/bcetienne/tools-go-token/validation"
)

const (
	passwordResetTokenMaxLength   int    = 32
	passwordResetTokenServiceEnum string = "PASSWORD_RESET"
	passwordResetTokenSchema      string = "go_auth"
	passwordResetTokenTable       string = "token"
)

type PasswordResetService struct {
	db           *sql.DB
	config       *lib.Config
	queryBuilder *lib.QueryBuilder
}

func NewPasswordResetService(ctx context.Context, db *sql.DB, config *lib.Config) (*PasswordResetService, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	service := &PasswordResetService{db, config, lib.NewQueryBuilder(passwordResetTokenSchema, passwordResetTokenTable, passwordResetTokenServiceEnum)}

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

func (prs *PasswordResetService) CreatePasswordResetToken(ctx context.Context, userID int) (*model.Token, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Parse duration from configuration
	duration, err := time.ParseDuration(*prs.config.TokenExpiry)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(duration)

	// Create a random token
	token, err := lib.GenerateRandomString(passwordResetTokenMaxLength)
	if err != nil {
		return nil, err
	}

	rt := model.NewToken(userID, token, passwordResetTokenServiceEnum, expiresAt)

	// Prepare transaction
	tx, err := prs.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err = tx.QueryRowContext(ctx, prs.queryBuilder.CreateToken(), rt.UserID, rt.TokenValue, rt.ExpiresAt).Scan(&rt.TokenID); err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return rt, nil
}

func (prs *PasswordResetService) VerifyPasswordResetToken(ctx context.Context, token string) (*bool, error) {
	if err := validation.IsIncomingTokenValid(token, passwordResetTokenMaxLength); err != nil {
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := prs.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var exists bool
	if err = tx.QueryRowContext(ctx, prs.queryBuilder.VerifyToken(), token).Scan(&exists); err != nil {
		return nil, err
	}

	return &exists, nil
}

func (prs *PasswordResetService) RevokePasswordResetToken(ctx context.Context, token string, userID int) error {
	if err := validation.IsIncomingTokenValid(token, passwordResetTokenMaxLength); err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := prs.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, prs.queryBuilder.RevokeToken(), userID, token)
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

func (prs *PasswordResetService) RevokeAllUserPasswordResetTokens(ctx context.Context, userID int) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := prs.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, prs.queryBuilder.RevokeAllUsersTokens(), userID)
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (prs *PasswordResetService) DeleteExpiredPasswordResetTokens(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := prs.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, prs.queryBuilder.FlushExpiredTokens())
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (prs *PasswordResetService) FlushPasswordResetTokens(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := prs.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, prs.queryBuilder.FlushAllTokens())
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (prs *PasswordResetService) FlushUserPasswordResetTokens(ctx context.Context, userID int) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare transaction
	tx, err := prs.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, prs.queryBuilder.FlushUserTokens(), userID)
	if err != nil {
		return err
	}

	_, err = result.RowsAffected()
	if err != nil {
		return err
	}

	return tx.Commit()
}
