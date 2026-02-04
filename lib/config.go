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
}

func NewConfig(issuer, jwtSecret, jwtExpiry, redisAddr, redisPwd string, redisDB int, refreshTokenTTL, passwordResetTTL *string) *Config {
	if refreshTokenTTL == nil {
		ttl := "1h"
		refreshTokenTTL = &ttl
	}
	if passwordResetTTL == nil {
		ttl := "10m"
		passwordResetTTL = &ttl
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
	}
}
