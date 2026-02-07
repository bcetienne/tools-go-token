package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/bcetienne/tools-go-token/validation"
	"github.com/redis/go-redis/v9"
)

const (
	redisStoreNameOTP         string = "otp"
	redisStoreNameOTPAttempts string = "otp:attempts"
	maxAttempts               int    = 5
)

// OTPService manages one-time password (OTP) generation, verification, and rate limiting.
// It uses Redis for storage with automatic expiration via TTL and bcrypt for secure hashing.
//
// Key features:
//   - Single active OTP per user (creating new OTP invalidates previous)
//   - OTP codes are hashed with bcrypt before storage (security)
//   - Rate limiting to prevent brute-force attacks (5 attempts max)
//   - Single-use tokens (auto-revoked after successful verification)
//   - Automatic expiration via Redis TTL
//
// Redis key patterns:
//   - OTP storage: "otp:{userID}" → bcrypt hash of OTP code
//   - Attempts tracking: "otp:attempts:{userID}" → counter (integer)
//   - Both keys have the same TTL and expire together
type OTPService struct {
	db       *redis.Client
	config   *lib.Config
	hasher   lib.PasswordHashInterface
	duration time.Duration
}

// OTPServiceInterface defines the methods for OTP management.
type OTPServiceInterface interface {
	CreateOTP(ctx context.Context, userID int) (*string, error)
	VerifyOTP(ctx context.Context, userID int, otp string) (bool, error)
	RevokeOTP(ctx context.Context, userID int) error
	RevokeAllOTPs(ctx context.Context) error
}

// NewOTPService creates a new OTP service instance with Redis persistence
// using the default bcrypt hasher (cost factor 14).
// Returns an error if the database client is nil or if OTPTTL is not configured.
//
// The service is initialized with:
//   - A bcrypt hasher (cost factor 14) for secure OTP storage
//   - Pre-parsed TTL duration for performance
//
// Parameters:
//   - ctx: Context for initialization (uses Background if nil)
//   - db: Redis client for OTP storage
//   - config: Configuration containing OTPTTL
//
// Returns:
//   - *OTPService: Initialized service ready for use
//   - error: Configuration or database validation errors
//
// Example:
//
//	otpService, err := service.NewOTPService(ctx, redisClient, config)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewOTPService(ctx context.Context, db *redis.Client, config *lib.Config) (*OTPService, error) {
	return NewOTPServiceWithHasher(ctx, db, config, nil)
}

// NewOTPServiceWithHasher creates a new OTP service instance with a custom hasher.
// This is primarily useful for testing with a lower bcrypt cost factor to speed up tests.
// If hasher is nil, uses the default hasher with cost factor 14.
//
// Parameters:
//   - ctx: Context for initialization (uses Background if nil)
//   - db: Redis client for OTP storage
//   - config: Configuration containing OTPTTL
//   - hasher: Custom password hasher (nil for default)
//
// Returns:
//   - *OTPService: Initialized service ready for use
//   - error: Configuration or database validation errors
//
// Example for testing:
//
//	hasher := lib.NewPasswordHashWithCost(4) // Fast for tests
//	otpService, err := service.NewOTPServiceWithHasher(ctx, redisClient, config, hasher)
func NewOTPServiceWithHasher(ctx context.Context, db *redis.Client, config *lib.Config, hasher lib.PasswordHashInterface) (*OTPService, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	if config.OTPTTL == nil {
		return nil, errors.New("one time password ttl is nil")
	}

	// Parse duration once during initialization
	duration, err := time.ParseDuration(*config.OTPTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid OTP TTL format: %w", err)
	}

	// Use default hasher if none provided
	if hasher == nil {
		hasher = lib.NewPasswordHash()
	}

	service := &OTPService{
		db:       db,
		config:   config,
		hasher:   hasher,
		duration: duration,
	}

	return service, nil
}

// CreateOTP generates a new 6-digit OTP code for the specified user.
// The code is hashed with bcrypt before storage for security.
// Creating a new OTP automatically invalidates any previous OTP for the user.
// Both the OTP and attempt counter are reset with fresh TTL.
//
// Security features:
//   - Code is hashed with bcrypt (cost 14) before storage
//   - Previous OTP is automatically invalidated
//   - Attempt counter is reset to 0
//   - Both OTP and attempts expire together (same TTL)
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier (must be > 0)
//
// Returns:
//   - *string: Pointer to the generated 6-digit OTP code (plaintext for sending via email/SMS)
//   - error: Validation or storage errors
//
// Example:
//
//	otp, err := otpService.CreateOTP(ctx, 123)
//	if err != nil {
//	    return err
//	}
//	// Send *otp to user via email: "Your code is: 387492"
//	sendEmail(userEmail, *otp)
func (otps *OTPService) CreateOTP(ctx context.Context, userID int) (*string, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	key := fmt.Sprintf("%s:%d", redisStoreNameOTP, userID)

	otp, err := lib.GenerateOTP()
	if err != nil {
		return nil, err
	}

	hash, err := otps.hasher.Hash(otp)
	if err != nil {
		return nil, err
	}

	err = otps.db.Set(ctx, key, hash, otps.duration).Err()
	if err != nil {
		return nil, err
	}

	// Reset attempts counter - if this fails, rollback OTP creation
	if err := otps.resetAttempts(ctx, userID); err != nil {
		// Best effort rollback: delete the OTP we just created
		_ = otps.db.Del(ctx, key)
		return nil, fmt.Errorf("failed to reset attempts counter: %w", err)
	}

	return &otp, nil
}

// VerifyOTP checks if the provided OTP code is valid for the user.
// Automatically increments the failed attempts counter on invalid attempts.
// If verification succeeds, the OTP is automatically revoked (single-use).
// Returns false if rate limit is exceeded (5 attempts).
//
// Verification flow:
//  1. Validates OTP format (6 numeric digits)
//  2. Checks rate limit (fails if >= 5 attempts)
//  3. Retrieves hashed OTP from Redis
//  4. Compares with bcrypt
//  5. On success: revokes OTP immediately (single-use)
//  6. On failure: increments attempts counter
//
// Security features:
//   - Rate limiting prevents brute force (max 5 attempts)
//   - Bcrypt comparison is timing-attack resistant
//   - Single-use enforcement (auto-revoke on success)
//   - Attempts counter incremented even if OTP not found (prevents enumeration)
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier (must be > 0)
//   - otp: The OTP code to verify (must be 6 digits)
//
// Returns:
//   - bool: true if OTP is valid and not rate-limited, false otherwise
//   - error: Validation errors, rate limit exceeded, or storage errors
//
// Example:
//
//	valid, err := otpService.VerifyOTP(ctx, 123, "387492")
//	if err != nil {
//	    if strings.Contains(err.Error(), "max attempts exceeded") {
//	        return errors.New("too many attempts, request new code")
//	    }
//	    return err
//	}
//	if !valid {
//	    return errors.New("invalid or expired OTP")
//	}
//	// OTP verified, proceed with authentication
func (otps *OTPService) VerifyOTP(ctx context.Context, userID int, otp string) (bool, error) {
	if userID <= 0 {
		return false, errors.New("invalid user id")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	otpValidation := validation.NewOTPValidation()
	if !otpValidation.ISOTPValid(otp) {
		return false, errors.New("invalid otp")
	}

	// Check rate limit before verification
	attemptsStr, err := otps.getAttempts(ctx, userID)
	if err != nil {
		return false, err
	}
	if attemptsStr != "" {
		attempts, err := strconv.Atoi(attemptsStr)
		if err != nil {
			return false, fmt.Errorf("corrupted attempts counter: %w", err)
		}
		if attempts >= maxAttempts {
			return false, errors.New("max attempts exceeded")
		}
	}

	val, err := otps.db.Get(ctx, fmt.Sprintf("%s:%d", redisStoreNameOTP, userID)).Result()
	if errors.Is(err, redis.Nil) {
		// OTP not found - increment attempts (best effort, ignore error)
		_, _ = otps.incrementAttempts(ctx, userID)
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if !otps.hasher.CheckHash(otp, val) {
		// Wrong OTP - increment attempts (best effort, ignore error)
		_, _ = otps.incrementAttempts(ctx, userID)
		return false, nil
	}

	// OTP is valid - revoke it immediately (single-use enforcement)
	if err := otps.RevokeOTP(ctx, userID); err != nil {
		return false, err
	}

	return true, nil
}

// RevokeOTP immediately invalidates the OTP and resets the attempt counter for a user.
// Safe to call even if no OTP exists (idempotent operation).
//
// Use cases:
//   - User requests a new OTP (old one is invalidated)
//   - Admin manually revokes a user's OTP
//   - Automatic revocation after successful verification
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier (must be > 0)
//
// Returns:
//   - error: Validation or storage errors
//
// Example:
//
//	err := otpService.RevokeOTP(ctx, 123)
//	if err != nil {
//	    log.Printf("Failed to revoke OTP: %v", err)
//	}
func (otps *OTPService) RevokeOTP(ctx context.Context, userID int) error {
	if userID <= 0 {
		return errors.New("invalid user id")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	err := otps.db.Del(ctx, fmt.Sprintf("%s:%d", redisStoreNameOTP, userID)).Err()
	if err != nil {
		return err
	}

	return otps.revokeAttempts(ctx, userID)
}

// RevokeAllOTPs revokes all OTP codes and attempt counters for all users.
// Used for emergency security measures or testing cleanup.
//
// Warning: This is a destructive operation that affects all users.
//
// Use cases:
//   - Security breach (invalidate all codes immediately)
//   - System maintenance
//   - Test cleanup
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//
// Returns:
//   - error: Storage errors encountered during revocation
//
// Example:
//
//	// Emergency: security breach detected
//	err := otpService.RevokeAllOTPs(ctx)
//	if err != nil {
//	    log.Fatal("Failed to revoke all OTPs: %v", err)
//	}
//	log.Println("All OTPs revoked successfully")
func (otps *OTPService) RevokeAllOTPs(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	keys := otps.db.Scan(ctx, 0, fmt.Sprintf("%s:*", redisStoreNameOTP), 0).Iterator()
	for keys.Next(ctx) {
		key := keys.Val()
		if err := otps.db.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("failed to delete otp key %s : %w", key, err)
		}
	}

	err := otps.revokeAllAttempts(ctx)
	if err != nil {
		return err
	}

	return keys.Err()
}

func (otps *OTPService) getAttempts(ctx context.Context, userID int) (string, error) {
	if userID <= 0 {
		return "", errors.New("invalid user id")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	val, err := otps.db.Get(ctx, fmt.Sprintf("%s:%d", redisStoreNameOTPAttempts, userID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return val, nil
}

func (otps *OTPService) incrementAttempts(ctx context.Context, userID int) (int, error) {
	if userID <= 0 {
		return 0, errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	key := fmt.Sprintf("%s:%d", redisStoreNameOTPAttempts, userID)

	// Check if key exists to avoid race condition between INCR and EXPIRE
	exists, err := otps.db.Exists(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	if exists == 0 {
		// Create key with TTL atomically (no race condition)
		err = otps.db.Set(ctx, key, 1, otps.duration).Err()
		if err != nil {
			return 0, err
		}
		return 1, nil
	}

	// Key exists with TTL already set, safe to increment
	newAttempts, err := otps.db.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	return int(newAttempts), nil
}

func (otps *OTPService) revokeAttempts(ctx context.Context, userID int) error {
	if userID <= 0 {
		return errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	return otps.db.Del(ctx, fmt.Sprintf("%s:%d", redisStoreNameOTPAttempts, userID)).Err()
}

func (otps *OTPService) revokeAllAttempts(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	keys := otps.db.Scan(ctx, 0, fmt.Sprintf("%s:*", redisStoreNameOTPAttempts), 0).Iterator()
	for keys.Next(ctx) {
		key := keys.Val()
		if err := otps.db.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("failed to delete otp attempt key %s : %w", key, err)
		}
	}

	return keys.Err()
}

func (otps *OTPService) resetAttempts(ctx context.Context, userID int) error {
	if userID <= 0 {
		return errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	return otps.db.Set(ctx, fmt.Sprintf("%s:%d", redisStoreNameOTPAttempts, userID), 0, otps.duration).Err()
}
