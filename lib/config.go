// Package lib provides core library components for the authentication module.
package lib

// Config holds the configuration for all authentication services.
// Contains JWT settings, Redis connection parameters, and TTL configurations.
//
// JWT Configuration:
//   - Issuer: Application identifier for JWT tokens
//   - JWTSecret: Secret key for signing and verifying JWTs (keep secure!)
//   - JWTExpiry: Duration string for access token expiration (e.g., "15m")
//
// Redis Configuration:
//   - RedisAddr: Redis server address (e.g., "localhost:6379")
//   - RedisPwd: Redis password (empty string if no authentication)
//   - RedisDB: Redis database number (0-15)
//
// TTL Configuration (pointers allow nil detection and default values):
//   - RefreshTokenTTL: Refresh token expiration (default: "1h")
//   - PasswordResetTTL: Password reset token expiration (default: "10m")
//   - OTPTTL: OTP code expiration (default: "10m")
//
// OTP Configuration:
//   - OTPSecret: Secret key for OTP generation (currently unused, reserved for TOTP)
type Config struct {
	Issuer           string
	JWTSecret        string
	JWTExpiry        string
	RedisAddr        string
	RedisPwd         string
	RedisDB          int
	RefreshTokenTTL  *string
	PasswordResetTTL *string
	OTPSecret        string
	OTPTTL           *string
}

// NewConfig creates a new configuration instance with default TTL values.
// If any TTL parameter is nil, a sensible default is applied.
//
// Default TTL values:
//   - RefreshTokenTTL: "1h" (balances security and user convenience)
//   - PasswordResetTTL: "10m" (short window for security)
//   - OTPTTL: "10m" (short window for security)
//
// Parameters:
//   - issuer: JWT issuer identifier (e.g., "myapp", "api.example.com")
//   - jwtSecret: Secret key for JWT signing (use strong random string)
//   - jwtExpiry: Access token duration (e.g., "15m", "1h")
//   - redisAddr: Redis server address (e.g., "localhost:6379", "redis:6379")
//   - redisPwd: Redis password (empty string "" if no auth)
//   - otpSecret: OTP secret key (reserved for future TOTP support)
//   - redisDB: Redis database number (0-15, typically 0)
//   - refreshTokenTTL: Refresh token TTL (nil for default "1h")
//   - passwordResetTTL: Reset token TTL (nil for default "10m")
//   - otpTTL: OTP code TTL (nil for default "10m")
//
// Returns:
//   - *Config: Initialized configuration with defaults applied
//
// Example:
//
//	// With explicit TTLs
//	refreshTTL := "24h"
//	resetTTL := "15m"
//	otpTTL := "5m"
//	config := lib.NewConfig("myapp", "jwt-secret-key", "15m",
//	    "localhost:6379", "", "otp-secret", 0,
//	    &refreshTTL, &resetTTL, &otpTTL)
//
//	// With default TTLs
//	config := lib.NewConfig("myapp", "jwt-secret-key", "15m",
//	    "localhost:6379", "", "", 0, nil, nil, nil)
func NewConfig(issuer, jwtSecret, jwtExpiry, redisAddr, redisPwd, otpSecret string, redisDB int, refreshTokenTTL, passwordResetTTL, otpTTL *string) *Config {
	if refreshTokenTTL == nil {
		ttl := "1h"
		refreshTokenTTL = &ttl
	}
	if passwordResetTTL == nil {
		ttl := "10m"
		passwordResetTTL = &ttl
	}
	if otpTTL == nil {
		ttl := "10m"
		otpTTL = &ttl
	}

	return &Config{
		Issuer:           issuer,
		JWTSecret:        jwtSecret,
		JWTExpiry:        jwtExpiry,
		RedisAddr:        redisAddr,
		RedisPwd:         redisPwd,
		RedisDB:          redisDB,
		RefreshTokenTTL:  refreshTokenTTL,
		PasswordResetTTL: passwordResetTTL,
		OTPSecret:        otpSecret,
		OTPTTL:           otpTTL,
	}
}
