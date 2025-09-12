# Go Token Authentication Module

A comprehensive Go module providing secure authentication and token management functionality with PostgreSQL persistence, JWT tokens, and robust validation.

## 🚀 Features

### Core Authentication Components
- **JWT Access Tokens**: Short-lived tokens for API authentication
- **Refresh Tokens**: Long-lived tokens stored in database for session management
- **Password Reset Tokens**: Secure tokens for password recovery workflows

### Security & Validation
- **Password Security**: Bcrypt hashing with configurable cost factor (14)
- **Password Validation**: Comprehensive rules (uppercase, lowercase, digits, special chars, length, blacklist)
- **Email Validation**: RFC-compliant email format validation
- **Token Validation**: Length and format validation for incoming tokens

### Database Management
- **PostgreSQL Integration**: Full schema and table management
- **Migration Support**: Automatic schema, enum, and table creation
- **Transaction Safety**: All database operations wrapped in transactions
- **Query Builder**: Type-safe SQL query generation

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Testing](#testing)
- [Contributing](#contributing)

## 🛠️ Installation

```bash
go get github.com/bcetienne/tools-go-token
```

### Dependencies

- Go 1.25+
- PostgreSQL 12+

### Required Go modules:
```go
require (
    github.com/golang-jwt/jwt/v5 v5.3.0
    github.com/google/uuid v1.6.0
    golang.org/x/crypto v0.41.0
)
```

## ⚡ Quick Start

### 1. Basic Setup

```go
package main

import (
    "context"
    "database/sql"
    "log"

    "github.com/bcetienne/tools-go-token/lib"
    "github.com/bcetienne/tools-go-token/service"
    "github.com/bcetienne/tools-go-token/validation"
    _ "github.com/lib/pq"
)

func main() {
    // Database connection
    db, err := sql.Open("postgres", "postgres://user:pass@localhost/dbname?sslmode=disable")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Configuration
    tokenExpiry := "24h"
    config := lib.NewConfig(
        "your-app.com",           // Issuer
        "your-jwt-secret-key",    // JWT Secret
        "15m",                    // JWT Expiry
        &tokenExpiry,             // Token Expiry
    )

    // Initialize services
    ctx := context.Background()
    refreshTokenService, err := service.NewRefreshTokenService(ctx, db, config)
    if err != nil {
        log.Fatal(err)
    }

    accessTokenService := service.NewAccessTokenService(config)
    passwordResetService, err := service.NewPasswordResetService(ctx, db, config)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Authentication services initialized successfully!")
}
```

### 2. Password Validation

```go
import "github.com/bcetienne/tools-go-token/validation"

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

### 3. Complete Authentication Flow

```go
import (
    modelRefreshToken "github.com/bcetienne/tools-go-token/model/refresh-token"
    "github.com/bcetienne/tools-go-token/lib"
)

func authenticationFlow() {
    // User data
    user := modelRefreshToken.NewAuthUser(1, "user-uuid", "user@example.com")
    
    // Hash password
    passwordHash := lib.NewPasswordHash()
    hashedPassword, _ := passwordHash.Hash("userPassword123!")
    
    // Create refresh token
    refreshToken, _ := refreshTokenService.CreateRefreshToken(ctx, user.GetUserID())
    
    // Create access token
    accessToken, _ := accessTokenService.CreateAccessToken(user)
    
    log.Printf("Refresh Token: %s", refreshToken.TokenValue)
    log.Printf("Access Token: %s", accessToken)
}
```

## ⚙️ Configuration

### Config Structure

```go
type Config struct {
    Issuer      string  // JWT issuer (e.g., "your-app.com")
    JWTSecret   string  // Secret key for JWT signing
    JWTExpiry   string  // JWT expiration duration (e.g., "15m")
    TokenExpiry *string // Database token expiration (e.g., "24h")
}
```

### Environment Variables (Recommended)

```bash
# .env file
JWT_ISSUER=your-app.com
JWT_SECRET=your-very-secure-secret-key-here
JWT_EXPIRY=15m
TOKEN_EXPIRY=24h
```

```go
// Loading from environment
import "os"

func loadConfig() *lib.Config {
    tokenExpiry := os.Getenv("TOKEN_EXPIRY")
    return lib.NewConfig(
        os.Getenv("JWT_ISSUER"),
        os.Getenv("JWT_SECRET"),
        os.Getenv("JWT_EXPIRY"),
        &tokenExpiry,
    )
}
```

## 📚 Usage Examples

### Email Validation

```go
import "github.com/bcetienne/tools-go-token/validation"

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

### Password Hashing & Verification

```go
import "github.com/bcetienne/tools-go-token/lib"

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

### Refresh Token Management

```go
func refreshTokenExample() {
    ctx := context.Background()
    userID := 123
    
    // Create refresh token
    token, err := refreshTokenService.CreateRefreshToken(ctx, userID)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Created token: %s", token.TokenValue)
    
    // Verify token
    exists, err := refreshTokenService.VerifyRefreshToken(ctx, token.TokenValue)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Token valid: %v", *exists)
    
    // Revoke token
    err = refreshTokenService.RevokeRefreshToken(ctx, token.TokenValue, userID)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("Token revoked successfully")
    
    // Cleanup expired tokens
    err = refreshTokenService.DeleteExpiredRefreshTokens(ctx)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("Expired tokens cleaned up")
}
```

### JWT Access Token Handling

```go
func accessTokenExample() {
    user := modelRefreshToken.NewAuthUser(1, "uuid", "user@example.com")
    
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
    
    log.Printf("Token valid for user: %d", claims.UserID)
}
```

### Password Reset Flow

```go
func passwordResetExample() {
    ctx := context.Background()
    userID := 456
    
    // Create password reset token
    resetToken, err := passwordResetService.CreatePasswordResetToken(ctx, userID)
    if err != nil {
        log.Fatal(err)
    }
    
    // Send token via email (implementation depends on your email service)
    sendPasswordResetEmail(user.Email, resetToken.TokenValue)
    
    // Later, when user submits reset form...
    // Verify the token
    valid, err := passwordResetService.VerifyPasswordResetToken(ctx, resetToken.TokenValue)
    if err != nil {
        log.Fatal(err)
    }
    
    if *valid {
        // Token is valid, allow password reset
        log.Println("Password reset token verified")
        // Update user password in your user service
        // Then revoke the token
        passwordResetService.RevokePasswordResetToken(ctx, resetToken.TokenValue, userID)
    }
}
```

## 🏗️ Architecture

### Project Structure

```
.
├── lib/                    # Core utilities
│   ├── config.go          # Configuration management
│   ├── misc.go            # Random string generation
│   ├── passwordHash.go    # Password hashing (bcrypt)
│   └── queryBuilder.go    # SQL query builder
├── validation/            # Validation logic
│   ├── email.go          # Email validation
│   ├── password.go       # Password validation
│   └── token.go          # Token validation
├── model/                # Data models
│   ├── token.go          # Base token model
│   └── refresh-token/    # Refresh token specific models
│       ├── authUser.go   # User authentication model
│       └── claim.go      # JWT claims model
├── service/              # Business logic
│   ├── accessToken.go    # JWT access token service
│   ├── refreshToken.go   # Refresh token service
│   └── passwordReset.go  # Password reset service
└── test/                 # Comprehensive tests
```

### Design Patterns Used

- **Interface Segregation**: Each service defines its own interface
- **Dependency Injection**: Services accept interfaces, not concrete types
- **Repository Pattern**: Database operations abstracted through services
- **Builder Pattern**: Query builder for SQL generation
- **Factory Pattern**: Constructor functions for all components

### Database Schema

The module automatically creates the following PostgreSQL structure:

```sql
-- Schema
CREATE SCHEMA IF NOT EXISTS go_auth;

-- Enum for token types
CREATE TYPE go_auth.token_type AS ENUM (
    'REFRESH_TOKEN',
    'PASSWORD_RESET'
);

-- Tokens table
CREATE TABLE IF NOT EXISTS go_auth.token (
    token_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    token_type go_auth.token_type NOT NULL,
    token_value VARCHAR NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    UNIQUE(token_value, token_type)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_token_user_id ON go_auth.token(user_id);
CREATE INDEX IF NOT EXISTS idx_token_token_value ON go_auth.token(token_value);
CREATE INDEX IF NOT EXISTS idx_token_expires_at ON go_auth.token(expires_at);
```

## 🧪 Testing

The project includes comprehensive tests using:

- **Unit Tests**: All components have individual unit tests
- **Integration Tests**: Database operations tested with TestContainers
- **Table-Driven Tests**: Multiple test cases per function
- **Mock Testing**: Interface-based testing for better isolation

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./validation
go test ./service
go test ./lib

# Run with verbose output
go test -v ./...
```

### Test Examples

The project includes extensive test coverage:

- Password validation with various scenarios
- Email validation with edge cases
- Token generation and verification
- Database operations with transactions
- Concurrent operations testing
- Error handling validation

## 📊 Performance Considerations

### Password Hashing
- Uses bcrypt with cost factor 14 (recommended for 2024+)
- Hashing takes ~200-300ms per operation (intentional for security)

### Database Operations
- All operations use transactions for data consistency
- Prepared statements prevent SQL injection
- Indexes on commonly queried columns
- Connection pooling recommended for production

### Token Security
- Refresh tokens: 255 characters, cryptographically secure
- Password reset tokens: 32 characters, short-lived
- JWT tokens: HS256 signing, configurable expiration

## 🔒 Security Features

### Password Security
- Minimum 8 characters (configurable)
- Must contain: uppercase, lowercase, digits, special characters
- Customizable blacklist for common passwords
- Bcrypt hashing with high cost factor

### Token Security
- Cryptographically secure random generation
- Database-stored tokens with expiration
- Revocation capabilities
- Automatic cleanup of expired tokens

### Database Security
- SQL injection prevention through prepared statements
- Transaction isolation
- Unique constraints on critical fields

## 🚀 Production Deployment

### Environment Configuration

```bash
# Production environment variables
export JWT_ISSUER="your-production-domain.com"
export JWT_SECRET="$(openssl rand -base64 32)"  # Generate secure secret
export JWT_EXPIRY="15m"
export TOKEN_EXPIRY="7d"
export DB_HOST="your-db-host"
export DB_PORT="5432"
export DB_NAME="your_production_db"
export DB_USER="your_db_user"
export DB_PASSWORD="your_secure_db_password"
```

### Database Setup

```sql
-- Create dedicated user for the application
CREATE USER token_app WITH PASSWORD 'secure_password';

-- Create database
CREATE DATABASE your_app_db OWNER token_app;

-- Grant necessary permissions
GRANT CONNECT ON DATABASE your_app_db TO token_app;
GRANT CREATE ON SCHEMA public TO token_app;
```

### Monitoring & Maintenance

```go
// Cleanup job (run periodically)
func cleanupExpiredTokens(services *Services) {
    ctx := context.Background()
    
    // Clean refresh tokens
    if err := services.RefreshToken.DeleteExpiredRefreshTokens(ctx); err != nil {
        log.Printf("Error cleaning refresh tokens: %v", err)
    }
    
    // Clean password reset tokens
    if err := services.PasswordReset.DeleteExpiredPasswordResetTokens(ctx); err != nil {
        log.Printf("Error cleaning password reset tokens: %v", err)
    }
}
```

### Development Setup

```bash
# Clone the repository
git clone https://github.com/bcetienne/tools-go-token.git
cd tools-go-token

# Install dependencies
go mod tidy

# Run tests
go test ./...

# Check formatting
go fmt ./...

# Run linter (if available)
golangci-lint run
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Related Projects

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) - JWT implementation for Go
- [golang.org/x/crypto](https://golang.org/x/crypto) - Extended cryptography packages
- [TestContainers](https://testcontainers.org/) - Integration testing with real dependencies

---

**Made with ❤️ and Go**