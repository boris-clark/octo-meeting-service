// Package storage wires the MySQL and Redis clients and exposes readiness
// checkers for them. It contains no domain queries.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
)

// OpenMySQL opens the pooled MySQL connection. It does not run migrations and
// never falls back to an embedded database; a bad DSN fails fast.
func OpenMySQL(cfg config.MySQLConfig) (*sql.DB, error) {
	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open mysql: %w", err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	return db, nil
}

// MySQLChecker reports MySQL readiness via a ping.
type MySQLChecker struct{ DB *sql.DB }

// Name implements health.Checker.
func (c MySQLChecker) Name() string { return "mysql" }

// Check pings the database within the caller's context.
func (c MySQLChecker) Check(ctx context.Context) error {
	if c.DB == nil {
		return fmt.Errorf("mysql not initialized")
	}
	return c.DB.PingContext(ctx)
}

// PingMySQL verifies connectivity during startup with a bounded timeout.
func PingMySQL(ctx context.Context, db *sql.DB, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return db.PingContext(ctx)
}
