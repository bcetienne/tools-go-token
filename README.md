# Go Token Authentication Module

A comprehensive Go module providing secure authentication and token management functionality with Redis persistence, JWT tokens, and robust validation.

## 🚀 Features

### Core authentication components
- **JWT access tokens**: Short-lived tokens for API authentication (stateless)
- **Refresh tokens**: Long-lived tokens stored in Redis for session management (multi-device support)
- **Password reset tokens**: Secure tokens for password recovery workflows (single active token per user)
- **OTP (One-Time Password)**: 6-digit codes for passwordless authentication via email (single active code per user)

### Security & validation
- **Password security**: Bcrypt hashing with configurable cost factor (14)
- **Password validation**: Comprehensive rules (uppercase, lowercase, digits, special chars, length, blacklist)
- **Email validation**: RFC-compliant email format validation
- **Token validation**: Length and format validation for incoming tokens

### Redis integration
- **Automatic expiration**: Built-in TTL (time-to-live) for token management with service-specific durations
- **High performance**: In-memory storage for fast token operations
- **Multi-token support**: Users can be logged in on multiple devices (RefreshToken - default 1h)
- **Single-token enforcement**: Only one password reset link or OTP active per user (PasswordReset - default 10m, OTP - default 10m)
- **No manual cleanup**: Redis automatically removes expired tokens
- **Flexible TTL**: Different expiration times for refresh tokens (long-lived), password reset tokens (short-lived), and OTP codes (very short-lived)

## 📋 Table of contents

- [Installation](#-installation)
- [Quick start](#-quick-start)
- [Configuration](#-configuration)
- [Usage examples](#-usage-examples)
- [Architecture](#-architecture)
- [Testing](#-testing)
- [Performance considerations](#-performance-considerations)
- [Security features](#-security-features)
- [Production deployment](#-production-deployment)
- [Development setup](#-development-setup)
- [License](#-license)
- [Related projects](#-related-projects)

## 🛠️ Installation

```bash
go get github.com/bcetienne/tools-go-token/v4
```

### ⚠️ Version 4.0 Breaking Changes

**User IDs are now strings** (was `int` in v3.x). This provides flexibility to support UUIDs, numeric IDs, or any unique identifier:

```go
// v3.x (old)
user := NewAuthUser(123, "uuid", "email@example.com")
token, _ := refreshService.CreateRefreshToken(ctx, 123)

// v4.x (new) - Numeric ID as string
user := NewAuthUser("123", "email@example.com")
token, _ := refreshService.CreateRefreshToken(ctx, "123")

// v4.x (new) - UUID
user := NewAuthUser("550e8400-e29b-41d4-a716-446655440000", "email@example.com")
token, _ := refreshService.CreateRefreshToken(ctx, "550e8400-e29b-41d4-a716-446655440000")
```

**JWT structure changed**: User ID moved to standard `Subject` claim (RFC 7519):
- Access user ID via `claim.Subject` (was `claim.UserID`)
- Email now in `claim.Email` custom claim (was in `Subject`)

See [CHANGELOG.md](CHANGELOG.md) for complete migration guide.

### Dependencies

- Go 1.25+
- Redis 6.0+

### Required Go modules:
```go
require (
    github.com/golang-jwt/jwt/v5 v5.3.0
    github.com/google/uuid v1.6.0
    github.com/redis/go-redis/v9 v9.7.0
    golang.org/x/crypto v0.41.0
)
```

## ⚡ Quick start

### 1. Basic setup

```go
package main

import (
    "context"
    "log"

    "github.com/bcetienne/tools-go-token/v4/lib"
    "github.com/bcetienne/tools-go-token/v4/service"
    "github.com/bcetienne/tools-go-token/v4/validation"
    "github.com/redis/go-redis/v9"
)

func main() {
    // Redis connection
    redisClient := redis.NewClient(&redis.Options{
        Addr:     "localhost:6379",
        Password: "", // no password set
        DB:       0,  // use default DB
    })
    defer redisClient.Close()

    // Test Redis connection
    ctx := context.Background()
    if err := redisClient.Ping(ctx).Err(); err != nil {
        log.Fatal("Cannot connect to Redis:", err)
    }

    // Configuration
    refreshTokenTTL := "7d"      // Long-lived refresh tokens
    passwordResetTTL := "15m"    // Short-lived reset tokens
    otpTTL := "10m"              // Short-lived OTP codes
    config := lib.NewConfig(
        "your-app.com",           // Issuer
        "your-jwt-secret-key",    // JWT Secret
        "15m",                    // JWT Expiry
        "localhost:6379",         // Redis Address
        "",                       // Redis Password
        "",                       // OTP Secret (for hashing)
        0,                        // Redis DB
        &refreshTokenTTL,         // Refresh Token TTL
        &passwordResetTTL,        // Password Reset TTL
        &otpTTL,                  // OTP TTL
    )

    // Initialize services
    refreshTokenService, err := service.NewRefreshTokenService(ctx, redisClient, config)
    if err != nil {
        log.Fatal(err)
    }

    accessTokenService := service.NewAccessTokenService(config)

    passwordResetService, err := service.NewPasswordResetService(ctx, redisClient, config)
    if err != nil {
        log.Fatal(err)
    }

    otpService, err := service.NewOTPService(ctx, redisClient, config)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Authentication services initialized successfully!")
}
```

### 2. Password validation

```go
import "github.com/bcetienne/tools-go-token/v4/validation"

func validateUserPassword() {
    validator := validation.NewPasswordValidation()

    // Configure custom rules
    validator.SetMinLength(12)
    validator.SetUnauthorizedWords([]string{"password", "123456", "admin"})

    // Validate password
    password := "MySecure123!"
    if validator.IsPasswordStrengthEnough(password) {
        log.Println("Password meets all requirements")
    } else {
        log.Println("Password does not meet security requirements")
    }
}
```

### 3. Complete authentication flow

```go
import (
    modelRefreshToken "github.com/bcetienne/tools-go-token/model/refresh-token"
    "github.com/bcetienne/tools-go-token/v4/lib"
)

func authenticationFlow() {
    // User data
    user := modelRefreshToken.NewAuthUser("1", "user@example.com")  // or use UUID: "550e8400-..."

    // Hash password
    passwordHash := lib.NewPasswordHash()
    hashedPassword, _ := passwordHash.Hash("userPassword123!")

    // Create refresh token (returns *string)
    refreshToken, _ := refreshTokenService.CreateRefreshToken(ctx, user.GetID())

    // Create access token
    accessToken, _ := accessTokenService.CreateAccessToken(user)

    log.Printf("Refresh Token: %s", *refreshToken)
    log.Printf("Access Token: %s", accessToken)
}
```

## ⚙️ Configuration

### Config structure

```go
type Config struct {
    Issuer           string  // JWT issuer (e.g., "your-app.com")
    JWTSecret        string  // Secret key for JWT signing
    JWTExpiry        string  // JWT expiration duration (e.g., "15m")
    RedisAddr        string  // Redis server address (e.g., "localhost:6379")
    RedisPwd         string  // Redis password (empty if no auth)
    OTPSecret        string  // OTP secret for hashing (optional, bcrypt used)
    RedisDB          int     // Redis database number (0-15)
    RefreshTokenTTL  *string // Refresh token expiration (e.g., "7d", default: "1h")
    PasswordResetTTL *string // Password reset token expiration (e.g., "15m", default: "10m")
    OTPTTL           *string // OTP code expiration (e.g., "10m", default: "10m")
}
```

**Why separate TTLs?**
- **Refresh tokens** are session tokens used for long-term authentication across multiple devices. They need longer expiration times (hours to days).
- **Password reset tokens** are security-sensitive and should expire quickly (minutes) to minimize the window for potential attacks.
- **OTP codes** are very short-lived authentication codes that should expire quickly (5-15 minutes) for security and to encourage timely use.

### Environment variables (recommended)

```bash
# .env file
JWT_ISSUER=your-app.com
JWT_SECRET=your-very-secure-secret-key-here
JWT_EXPIRY=15m
REFRESH_TOKEN_TTL=7d
PASSWORD_RESET_TTL=15m
OTP_TTL=10m
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
```

```go
// Loading from environment
import (
    "os"
    "strconv"
)

func loadConfig() *lib.Config {
    redisDB, _ := strconv.Atoi(os.Getenv("REDIS_DB"))
    refreshTokenTTL := os.Getenv("REFRESH_TOKEN_TTL")
    passwordResetTTL := os.Getenv("PASSWORD_RESET_TTL")
    otpTTL := os.Getenv("OTP_TTL")

    return lib.NewConfig(
        os.Getenv("JWT_ISSUER"),
        os.Getenv("JWT_SECRET"),
        os.Getenv("JWT_EXPIRY"),
        os.Getenv("REDIS_ADDR"),
        os.Getenv("REDIS_PASSWORD"),
        "",                    // OTP Secret (empty, bcrypt used)
        redisDB,
        &refreshTokenTTL,      // nil uses default "1h"
        &passwordResetTTL,     // nil uses default "10m"
        &otpTTL,               // nil uses default "10m"
    )
}
```

## 📚 Usage examples

### Email validation

```go
import "github.com/bcetienne/tools-go-token/v4/validation"

func validateEmail() {
    emailValidator := validation.NewEmailValidation()

    emails := []string{
        "valid@example.com",
        "invalid.email",
        "user+tag@domain.co.uk",
    }

    for _, email := range emails {
        if emailValidator.IsValidEmail(email) {
            log.Printf("✅ %s is valid", email)
        } else {
            log.Printf("❌ %s is invalid", email)
        }
    }
}
```

### Password hashing & verification

```go
import "github.com/bcetienne/tools-go-token/v4/lib"

func passwordExample() {
    hasher := lib.NewPasswordHash()

    password := "userPassword123!"

    // Hash password
    hash, err := hasher.Hash(password)
    if err != nil {
        log.Fatal(err)
    }

    // Verify password
    isValid := hasher.CheckHash(password, hash)
    log.Printf("Password verification: %v", isValid)

    // Wrong password
    isValid = hasher.CheckHash("wrongPassword", hash)
    log.Printf("Wrong password verification: %v", isValid) // false
}
```

### Refresh token management (multi-device support)

```go
func refreshTokenExample() {
    ctx := context.Background()
    userID := "123"  // String ID - can be UUID or numeric

    // Create refresh token (user can have multiple active tokens)
    token, err := refreshTokenService.CreateRefreshToken(ctx, userID)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Created token: %s", *token)

    // Verify token
    valid, err := refreshTokenService.VerifyRefreshToken(ctx, userID, *token)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Token valid: %v", valid)

    // Revoke specific token (e.g., logout from one device)
    err = refreshTokenService.RevokeRefreshToken(ctx, *token, userID)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("Token revoked successfully")

    // Revoke all user tokens (e.g., user changes password)
    err = refreshTokenService.RevokeAllUserRefreshTokens(ctx, userID)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("All user tokens revoked")

    // Emergency: revoke ALL tokens (e.g., security breach)
    err = refreshTokenService.RevokeAllRefreshTokens(ctx)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("All tokens revoked")
}
```

### JWT access token handling

```go
func accessTokenExample() {
    user := modelRefreshToken.NewAuthUser("1", "user@example.com")

    // Create access token
    token, err := accessTokenService.CreateAccessToken(user)
    if err != nil {
        log.Fatal(err)
    }

    // Verify access token
    claims, err := accessTokenService.VerifyAccessToken(token)
    if err != nil {
        if errors.Is(err, jwt.ErrTokenExpired) {
            log.Println("Token expired - refresh needed")
            // Handle token refresh logic
        } else {
            log.Printf("Token verification failed: %v", err)
        }
        return
    }

    log.Printf("Token valid for user: %s", claims.Subject)  // User ID now in Subject claim
}
```

### Password reset flow (single active token)

```go
func passwordResetExample() {
    ctx := context.Background()
    userID := "456"  // String ID

    // Create password reset token (invalidates previous token automatically)
    resetToken, err := passwordResetService.CreatePasswordResetToken(ctx, userID)
    if err != nil {
        log.Fatal(err)
    }

    // Send token via email (implementation depends on your email service)
    sendPasswordResetEmail(user.Email, *resetToken)

    // Later, when user submits reset form...
    // Verify the token
    valid, err := passwordResetService.VerifyPasswordResetToken(ctx, userID, *resetToken)
    if err != nil {
        log.Fatal(err)
    }

    if valid {
        // Token is valid, allow password reset
        log.Println("Password reset token verified")
        // Update user password in your user service
        // Then revoke the token (requires correct token for security)
        passwordResetService.RevokePasswordResetToken(ctx, userID, *resetToken)
    }
}
```

### OTP (One-Time Password) passwordless authentication

```go
func otpAuthenticationExample() {
    ctx := context.Background()
    userID := "789"  // String ID

    // === STEP 1: User requests OTP ===
    // Create 6-digit OTP code (invalidates previous code automatically)
    otp, err := otpService.CreateOTP(ctx, userID)
    if err != nil {
        log.Fatal(err)
    }

    // Send OTP via email (implementation depends on your email service)
    sendOTPEmail(user.Email, *otp) // e.g., "Your code is: 387492"
    log.Printf("OTP sent to user: %s", *otp)

    // === STEP 2: User submits OTP ===
    userSubmittedOTP := "387492" // From user input

    // Verify the OTP
    valid, err := otpService.VerifyOTP(ctx, userID, userSubmittedOTP)
    if err != nil {
        // Check for specific errors
        if strings.Contains(err.Error(), "max attempts exceeded") {
            log.Println("Too many failed attempts. Please request a new code.")
            return
        }
        if strings.Contains(err.Error(), "invalid otp") {
            log.Println("Invalid OTP format")
            return
        }
        log.Fatal(err)
    }

    if valid {
        // OTP is valid and has been automatically revoked (single-use)
        log.Println("OTP verified successfully! User is authenticated.")

        // Create session tokens for the user
        refreshToken, _ := refreshTokenService.CreateRefreshToken(ctx, userID)
        accessToken, _ := accessTokenService.CreateAccessToken(user)

        log.Printf("User logged in with refresh token: %s", *refreshToken)
    } else {
        // OTP is invalid, expired, or user doesn't exist
        log.Println("Invalid or expired OTP code")
    }
}

// Additional OTP management functions
func otpManagementExample() {
    ctx := context.Background()
    userID := "789"  // String ID

    // Revoke a specific user's OTP (e.g., user requests new code)
    err := otpService.RevokeOTP(ctx, userID)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("OTP revoked")

    // Emergency: revoke ALL OTPs (e.g., security breach)
    err = otpService.RevokeAllOTPs(ctx)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("All OTPs revoked")
}
```

## 🏗️ Architecture

### Project structure

```
.
├── lib/                    # Core utilities
│   ├── config.go           # Configuration management
│   ├── misc.go             # Random string & OTP generation
│   ├── passwordHash.go     # Password hashing (bcrypt)
│   └── redisClient.go      # Redis client utilities
├── validation/             # Validation logic
│   ├── email.go            # Email validation
│   ├── password.go         # Password validation
│   ├── token.go            # Token validation
│   └── otp.go              # OTP validation
├── model/                  # Data models
│   └── refresh-token/      # Refresh token specific models
│       ├── authUser.go     # User authentication model
│       └── claim.go        # JWT claims model
├── service/                # Business logic
│   ├── accessToken.go      # JWT access token service (stateless)
│   ├── refreshToken.go     # Refresh token service (Redis)
│   ├── passwordReset.go    # Password reset service (Redis)
│   └── otp.go              # OTP service (Redis)
└── test/                   # Comprehensive tests
```

### Design patterns used

- **Interface segregation**: Each service defines its own interface
- **Dependency injection**: Services accept interfaces, not concrete types
- **Repository pattern**: Token storage abstracted through services
- **Factory pattern**: Constructor functions for all components
- **Strategy pattern**: Different token storage strategies (multi vs single)

### Redis key patterns

The module uses different Redis key patterns for different token types:

#### RefreshToken (multi-device support)
```
Pattern: refresh:{userID}:{token}
Value: "1"
TTL: RefreshTokenTTL (default: 1h, recommended: 7d for production)

Example:
  refresh:123:abc...xyz → "1" (expires in 7d)
  refresh:123:def...uvw → "1" (expires in 7d)
  refresh:456:ghi...rst → "1" (expires in 7d)

Allows multiple active tokens per user for multi-device sessions.
Long TTL enables persistent sessions without frequent re-authentication.
```

#### PasswordReset (single active token)
```
Pattern: password_reset:{userID}
Value: {token}
TTL: PasswordResetTTL (default: 10m, recommended: 15m-30m)

Example:
  password_reset:123 → "abc123xyz..." (expires in 15m)
  password_reset:456 → "def456uvw..." (expires in 30m)

Only one active reset link per user. Creating new token invalidates previous one.
Short TTL minimizes security risk if reset email is compromised.
```

#### OTP (single active code per user)
```
Pattern OTP: otp:{userID}
Value: {bcrypt_hash_of_6_digit_code}
TTL: OTPTTL (default: 10m, recommended: 5m-15m)

Pattern Attempts: otp:attempts:{userID}
Value: {attempt_count}
TTL: Same as OTP

Example:
  otp:123 → "$2a$14$..." (bcrypt hash, expires in 10m)
  otp:attempts:123 → "2" (2 failed attempts, expires in 10m)

Only one active OTP code per user. Creating new code invalidates previous one.
Rate limiting: Maximum 5 verification attempts before blocking.
Single-use: OTP is automatically revoked after successful verification.
Secure: Codes are hashed with bcrypt before storage (cost factor 14).
```

### Token lifecycle

**RefreshToken** (multi-token per user):
1. **Create**: `CreateRefreshToken(ctx, userID string)` → Returns `*string`
2. **Verify**: `VerifyRefreshToken(ctx, userID string, token string)` → Checks if key exists
3. **Revoke**: `RevokeRefreshToken(ctx, token string, userID string)` → Deletes specific token
4. **RevokeAllUser**: Deletes all tokens for one user (password change)
5. **RevokeAll**: Emergency revocation of ALL tokens (security breach)
6. **Expiration**: Automatic via Redis TTL

**PasswordReset** (single token per user):
1. **Create**: `CreatePasswordResetToken(ctx, userID string)` → Returns `*string`, invalidates previous
2. **Verify**: `VerifyPasswordResetToken(ctx, userID string, token string)` → Retrieves and compares token
3. **Revoke**: `RevokePasswordResetToken(ctx, userID string, token string)` → Verifies token before deletion (security)
4. **RevokeAll**: Emergency revocation of ALL reset tokens
5. **Expiration**: Automatic via Redis TTL

**OTP** (single code per user, rate-limited):
1. **Create**: `CreateOTP(ctx, userID string)` → Returns `*string` (6-digit code), invalidates previous, resets attempts
2. **Verify**: `VerifyOTP(ctx, userID, code)` → Checks bcrypt hash, enforces rate limit (5 attempts), auto-revokes on success
3. **Revoke**: `RevokeOTP(ctx, userID)` → Deletes OTP and attempts counter
4. **RevokeAll**: Emergency revocation of ALL OTPs
5. **Expiration**: Automatic via Redis TTL for both OTP and attempts counter

## 🧪 Testing

The project includes comprehensive tests using:

- **Unit tests**: All components have individual unit tests
- **Integration tests**: Redis operations tested with TestContainers
- **Table-Driven tests**: Multiple test cases per function
- **Concurrent testing**: Multi-threaded operation validation

### Running tests

```bash
# Run all tests (requires Docker for TestContainers)
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./validation
go test ./service
go test ./lib

# Run with verbose output
go test -v ./...

# Run specific test
go test -v -run TestCreateRefreshToken ./test/service
```

### Test coverage

The project includes 116 comprehensive tests:

- **AccessToken**: 4 tests (JWT creation, verification, expiration)
- **RefreshToken**: 32 tests (multi-token support, revocation, expiration)
- **PasswordReset**: 40 tests (single-token enforcement, security, concurrency)
- **OTP**: 40 tests (rate limiting, single-use, bcrypt hashing, expiration, uniqueness)
- **Validation**: Password strength, email format, token validation, OTP format
- **Utilities**: Password hashing, random string generation, OTP generation

## 📊 Performance considerations

### Password hashing
- Uses bcrypt with cost factor 14 (recommended for 2024+)
- Hashing takes ~200-300ms per operation (intentional for security)

### Redis operations
- All operations are in-memory (sub-millisecond response times)
- Connection pooling built into go-redis client
- Automatic reconnection on connection loss
- Pipeline support for batch operations

### Token security
- Refresh tokens: 255 characters, cryptographically secure
- Password reset tokens: 32 characters, short-lived
- JWT tokens: HS256 signing, configurable expiration

## 🔒 Security features

### Password security
- Minimum 8 characters (configurable)
- Must contain: uppercase, lowercase, digits, special characters
- Customizable blacklist for common passwords
- Bcrypt hashing with high cost factor

### Token security
- Cryptographically secure random generation (`crypto/rand`)
- Redis-stored tokens with automatic expiration (TTL)
- Revocation capabilities (individual, user-specific, global)
- Single active reset token per user (prevents multiple concurrent reset attempts)
- PasswordReset revocation requires correct token (prevents unauthorized revocation)

### OTP security
- 6-digit codes generated with `crypto/rand` (cryptographically secure)
- Bcrypt hashing with cost factor 14 (~200ms per operation, prevents brute force)
- Rate limiting: Maximum 5 verification attempts per code
- Single-use enforcement: Auto-revoked after successful verification
- Single active code per user (creating new code invalidates previous)
- Short TTL (default 10 minutes, configurable 5-15 minutes)
- Attempt counter expires with OTP (prevents indefinite blocking)

### Redis security
- Connection authentication support
- TLS/SSL support for encrypted connections
- No sensitive data stored (tokens are random strings)

## 🚀 Production deployment

### Environment configuration

```bash
# Production environment variables
export JWT_ISSUER="your-production-domain.com"
export JWT_SECRET="$(openssl rand -base64 32)"  # Generate secure secret
export JWT_EXPIRY="15m"

# Token TTL configuration
export REFRESH_TOKEN_TTL="7d"    # Long-lived session tokens
export PASSWORD_RESET_TTL="15m"  # Short-lived security tokens
export OTP_TTL="10m"             # Very short-lived OTP codes

# Redis configuration
export REDIS_ADDR="your-redis-host:6379"
export REDIS_PASSWORD="your-secure-redis-password"
export REDIS_DB="0"
export REDIS_TLS_ENABLED="true"  # Use TLS in production
```

### Redis setup

```bash
# Install Redis (Ubuntu/Debian)
sudo apt update
sudo apt install redis-server

# Configure Redis for production
sudo nano /etc/redis/redis.conf

# Key settings:
# - requirepass your_strong_password
# - maxmemory 256mb
# - maxmemory-policy allkeys-lru
# - protected-mode yes
# - bind 127.0.0.1 ::1

# Restart Redis
sudo systemctl restart redis-server

# Verify Redis is running
redis-cli ping
```

### Production checklist

- [ ] Use strong JWT secret (32+ random bytes)
- [ ] Enable Redis authentication (`requirepass`)
- [ ] Use TLS for Redis connections in production
- [ ] Set appropriate token expiry times:
  - [ ] RefreshTokenTTL: 7d-30d (balance security vs user experience)
  - [ ] PasswordResetTTL: 15m-30m (minimize security window)
  - [ ] OTPTTL: 5m-15m (very short window for OTP codes)
  - [ ] JWTExpiry: 15m-1h (short-lived access tokens)
- [ ] Configure Redis `maxmemory` policy
- [ ] Monitor Redis memory usage
- [ ] Set up Redis persistence (RDB or AOF) if needed
- [ ] Implement rate limiting on token creation endpoints
- [ ] Log token operations for security auditing

### Docker deployment

```dockerfile
# Dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
CMD ["./main"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  app:
    build: .
    environment:
      - JWT_ISSUER=${JWT_ISSUER}
      - JWT_SECRET=${JWT_SECRET}
      - JWT_EXPIRY=15m
      - REFRESH_TOKEN_TTL=7d
      - PASSWORD_RESET_TTL=15m
      - OTP_TTL=10m
      - REDIS_ADDR=redis:6379
      - REDIS_PASSWORD=${REDIS_PASSWORD}
      - REDIS_DB=0
    depends_on:
      - redis

volumes:
  redis-data:
```

### Monitoring

```go
// Health check endpoint
func healthCheck(redisClient *redis.Client) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    return redisClient.Ping(ctx).Err()
}

// Metrics to monitor
// - Token creation rate
// - Token verification rate
// - Token revocation rate
// - Redis memory usage
// - Redis connection errors
```

## 📝 Development setup

```bash
# Clone the repository
git clone https://github.com/bcetienne/tools-go-token.git
cd tools-go-token

# Install dependencies
go mod tidy

# Start Redis for local development
docker run -d -p 6379:6379 redis:7-alpine

# Run tests
go test ./...

# Check formatting
go fmt ./...

# Run linter (if available)
golangci-lint run
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Related projects

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) - JWT implementation for Go
- [redis/go-redis](https://github.com/redis/go-redis) - Redis client for Go
- [golang.org/x/crypto](https://golang.org/x/crypto) - Extended cryptography packages
- [TestContainers](https://testcontainers.org/) - Integration testing with real dependencies

---

**Made with ❤️ and Go**
