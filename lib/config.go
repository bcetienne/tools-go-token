package lib

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
