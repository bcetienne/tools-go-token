package service

import (
	"context"
	"database/sql"
	"log"
	"os"
	"testing"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	db     *sql.DB
	config *lib.Config
	schema = "go_auth"
	table  = "token"
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	database := "go_auth_module_test"
	username := "user"
	password := "password"

	postgresContainer, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase(database),
		postgres.WithUsername(username),
		postgres.WithPassword(password),
		postgres.BasicWaitStrategies(),
	)

	defer func() {
		if err = testcontainers.TerminateContainer(postgresContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()
	if err != nil {
		log.Printf("failed to start container: %s", err)
		return
	}

	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Printf("failed to get connection string: %s", err)
		return
	}

	// Connect to database
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Cannot to connect to database: %s", err)
	}
	defer db.Close()

	// Check that the connection is established
	err = db.Ping()
	if err != nil {
		log.Fatalf("Cannot ping database: %s", err)
	}

	// Initialize fake config
	tokenExpiry := "24h"
	config = &lib.Config{TokenExpiry: &tokenExpiry}

	// Run tests
	exitCode := m.Run()

	// Exit with the tests exit code
	os.Exit(exitCode)
}
