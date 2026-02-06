# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
