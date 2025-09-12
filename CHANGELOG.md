# Changelog

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
