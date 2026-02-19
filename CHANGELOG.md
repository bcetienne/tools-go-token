# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.0] - 2026-02-19

### Added

- New `model/auth` package with `User`, `UserInterface`, and `Claim` types
  - `auth.NewUser(id, email string)` replaces `refresh_token.NewAuthUser`
  - `auth.User` replaces `refresh_token.AuthUser`
  - `auth.UserInterface` replaces `refresh_token.AuthUserInterface`
  - `auth.Claim` replaces `refresh_token.Claim`

### Deprecated

- `model/refresh-token` models moved to `model/auth` — will be removed in v5.0.0
  - `refresh_token.AuthUser` → use `auth.User`
  - `refresh_token.AuthUserInterface` → use `auth.UserInterface`
  - `refresh_token.Claim` → use `auth.Claim`
  - `refresh_token.NewAuthUser` → use `auth.NewUser`
  - Aliases are in place: existing code continues to compile without changes

### Internal

- `service/accessToken.go` updated to use `model/auth` types directly

---

## [4.0.0] - 2026-02-10

### Changed - BREAKING

- **User ID Type**: All user IDs changed from `int` to `string` across all services
  - `RefreshTokenService`: `CreateRefreshToken(ctx, userID string)` (was `int`)
  - `PasswordResetService`: `CreatePasswordResetToken(ctx, userID string)` (was `int`)
  - `OTPService`: `CreateOTP(ctx, userID string)` (was `int`)
  - Validation: User IDs validated as non-empty strings (was `> 0` for ints)
- **AuthUser Model**: Unified identifier structure
  - Old: `NewAuthUser(userID int, uuid string, email string)` with separate `UserID` and `UserUUID` fields
  - New: `NewAuthUser(id string, email string)` with single `ID` field
  - Supports UUIDs, numeric IDs as strings, or any unique identifier
- **JWT Claim Structure**: Aligned with RFC 7519 standards
  - User ID moved from custom `user_id` claim to standard `sub` (Subject) claim
  - Email moved from `sub` to custom `email` claim
  - Access user ID via `claim.Subject` instead of `claim.UserID`
- **Module Path**: Updated to `github.com/bcetienne/tools-go-token/v3` for semantic versioning

### Benefits

- **Platform Flexibility**: Support for both UUID-based and numeric ID systems
- **Standards Compliance**: JWT tokens now follow RFC 7519 recommendations
- **Unified API**: Single ID field simplifies user identity management
- **Type Safety**: String IDs prevent accidental ID confusion across different platforms

### Migration Guide

```go
// v3.x (old)
user := NewAuthUser(123, "550e8400-...", "user@example.com")
token, _ := refreshService.CreateRefreshToken(ctx, 123)
userID := claim.UserID  // int

// v4.x (new)
user := NewAuthUser("123", "user@example.com")  // or UUID: "550e8400-..."
token, _ := refreshService.CreateRefreshToken(ctx, "123")
userID := claim.Subject  // string
```

### Implementation Details

- Redis key patterns remain compatible: `refresh:{userID}:{token}`, `password_reset:{userID}`, `otp:{userID}`
- All 116 tests updated and passing
- Complete documentation update in CLAUDE.md and README.md

---

## [3.1.0] - 2026-02-06

### Added
- Complete godoc documentation for all public API elements (36 items)
  - Service layer: AccessTokenService, RefreshTokenService, PasswordResetService
  - Validation layer: IsIncomingTokenValid function
  - Library layer: Config and RedisClient types
  - Model layer: AuthUser and Claim types
- Documentation follows godoc standards with examples and detailed descriptions

### Fixed
- test/lib/config_test.go: Add missing otpSecret and otpTTL parameters to NewConfig calls (8 fixes)
- test/service/otp_test.go: Fix TestOTPInvalidConfig to expect error from NewOTPService
- All tests now pass (exit code 0)

## [3.0.0] - 2026-02-06

### Added
- **OTP (One-Time Password) service** for passwordless authentication via email
  - 6-digit numeric codes generated with crypto/rand
  - Bcrypt hashing (cost factor 14) for secure storage in Redis
  - Rate limiting: maximum 5 verification attempts per OTP
  - Single-use enforcement: auto-revoked after successful verification
  - Single active code per user (creating new code invalidates previous)
  - Configurable TTL (default: 10 minutes)
  - Automatic expiration via Redis TTL for both OTP and attempts counter
- OTP validation module (`validation/otp.go`)
- GenerateOTP function in `lib/misc.go`
- 40 comprehensive tests for OTP service (116 total tests in project)
- Complete OTP documentation in README.md

### Changed
- **BREAKING**: `lib.NewConfig()` signature changed - added `otpSecret` and `otpTTL` parameters
  - Old: `NewConfig(issuer, jwtSecret, jwtExpiry, redisAddr, redisPwd, redisDB, refreshTokenTTL, passwordResetTTL)`
  - New: `NewConfig(issuer, jwtSecret, jwtExpiry, redisAddr, redisPwd, otpSecret, redisDB, refreshTokenTTL, passwordResetTTL, otpTTL)`
- Updated README with OTP usage examples, Redis key patterns, and security considerations
- Test count: 76 → 116 tests

### Fixed
- Race condition in OTP `incrementAttempts` (INCR then EXPIRE) - now uses atomic SET operations
- Rate limiting now checks before OTP verification (prevents brute force attacks)

### Security
- OTP codes hashed with bcrypt (cost 14) preventing rainbow table attacks
- Rate limiting prevents brute force (5 attempts max)
- Automatic TTL expiration for both OTP and attempts counter
- Single-use tokens prevent replay attacks

---

## [2.0.0] - 2026-02-04

### Changed
- **BREAKING**: Migrated from PostgreSQL to Redis for token storage
  - Removed PostgreSQL dependencies and query builder
  - Removed automatic schema/table management
  - All tokens now stored in Redis with automatic TTL expiration
- **BREAKING**: Simplified service initialization (no more database migrations)
- Refactored RefreshToken service for Redis storage
  - Multi-token pattern: `refresh:{userID}:{token}`
  - Value: "1" (existence check)
- Refactored PasswordReset service for Redis storage
  - Single-token pattern: `password_reset:{userID}`
  - Value: token string (comparison check)
- Updated all tests to use TestContainers with Redis instead of PostgreSQL
- Complete README rewrite with Redis-specific documentation

### Added
- Redis client utilities (`lib/redisClient.go`)
- Automatic token expiration via Redis TTL
- Flexible TTL configuration (RefreshTokenTTL, PasswordResetTTL)

### Removed
- PostgreSQL dependencies
- Query builder module (`lib/queryBuilder.go`)
- Token model (`model/token.go`)
- Database migration system

### Performance
- Significantly faster operations (in-memory Redis vs disk-based PostgreSQL)
- No manual cleanup jobs needed (Redis TTL handles expiration)
- Connection pooling built into go-redis client

---

## [1.0.0] - 2025-09-12

### Added
- JWT Access Token service with secure authentication
- Refresh Tokens service with PostgreSQL persistence
- Password Reset service with temporary tokens
- Password validation (complexity, length, prohibited words)
- RFC-compliant email validation
- Secure password hashing with bcrypt
- Automatic management of PostgreSQL schemas and tables
- Comprehensive testing with TestContainers
- Complete documentation

### Security
- Bcrypt with cost factor 14
- Cryptographically secure tokens
- Protection against SQL injection
- Strict validation of user input
