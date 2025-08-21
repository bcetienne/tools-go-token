package refresh_token

type Config struct {
	Issuer             string
	JWTSecret          string
	JWTExpiry          string
	RefreshTokenExpiry string
}

func NewConfig(issuer, JWTSecret, JWTExpiry, RefreshTokenExpiry string) *Config {
	return &Config{
		Issuer:             issuer,
		JWTSecret:          JWTSecret,
		JWTExpiry:          JWTExpiry,
		RefreshTokenExpiry: RefreshTokenExpiry,
	}
}
