package lib

type Config struct {
	Issuer      string
	JWTSecret   string
	JWTExpiry   string
	TokenExpiry *string
}

func NewConfig(issuer, jwtSecret, jwtExpiry string, tokenExpiry *string) *Config {
	return &Config{issuer, jwtSecret, jwtExpiry, tokenExpiry}
}
