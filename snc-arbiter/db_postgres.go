// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"embed"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// postgresMigrations embeds the goose migration set into the binary itself,
// so a deploy only ever ships one file (the compiled snc-arbiter binary) --
// no separate .sql files need to be copied alongside it, matching how
// deploy.sh already ships every other service as a single binary.
//
//go:embed migrations/postgres/*.sql
var postgresMigrations embed.FS

// isPostgresDSN reports whether path is a Postgres connection string rather
// than a SQLite file path -- the one place the arbiter decides which
// database engine to talk to, controlled entirely by --db's value/format,
// no separate flag. See openDB in db.go.
func isPostgresDSN(path string) bool {
	return strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://")
}

// openPostgresDB opens a Postgres connection pool, runs any pending goose
// migrations (embedded, see postgresMigrations above), and returns a *DB
// wrapping it -- the exact same wrapper type openDB's SQLite path returns,
// so every one of the ~280 call sites elsewhere in the package works
// unchanged regardless of which engine is actually behind d.db.
func openPostgresDB(dsn string) (*DB, error) {
	db, err := sqlx.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	// Connection pool sizing: a deliberate, chosen value, not left at the
	// driver default (see plan's "Connection pool sizing" note -- this is
	// not just "not 1 anymore" the way SQLite's SetMaxOpenConns(1) was).
	// 25 is a modest starting point, well under Postgres's default
	// max_connections=100, leaving headroom for admin/replication/psql
	// connections alongside the arbiter's own pool; revisit under real
	// production load if this ever becomes a bottleneck.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	// A hot standby (streaming replica) rejects ANY write-classified
	// statement outright, even a no-op CREATE TABLE IF NOT EXISTS on a
	// table that already exists -- Postgres classifies read vs write by
	// statement type before execution, not by whether it would actually
	// change anything. goose.Up unconditionally issues exactly that (via
	// its internal EnsureDBVersion) on every single call, not just on a
	// first-ever run, so running it here against a replica fails every
	// time with "cannot execute CREATE TABLE in a read-only transaction" --
	// confirmed live, 2026-08-16, against the arbiter standby. That error
	// propagates up through main()'s "db: %v" -> os.Exit(1), so a replica
	// arbiter process would crash-loop forever under Restart=on-failure.
	// Skip migrations entirely when this connection is a replica: the
	// schema arrives for free via streaming replication from whichever
	// instance actually is the primary and DOES run migrations.
	var inRecovery bool
	if err := db.Get(&inRecovery, "SELECT pg_is_in_recovery()"); err != nil {
		return nil, fmt.Errorf("check pg_is_in_recovery: %w", err)
	}
	if inRecovery {
		logInfof("db: postgres is a hot standby (pg_is_in_recovery=true) — skipping goose migrations, schema arrives via streaming replication")
		return &DB{db: &rebindingDB{db}}, nil
	}

	goose.SetBaseFS(postgresMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return nil, fmt.Errorf("goose: set dialect: %w", err)
	}
	if err := goose.Up(db.DB, "migrations/postgres"); err != nil {
		return nil, fmt.Errorf("goose: migrate: %w", err)
	}

	return &DB{db: &rebindingDB{db}}, nil
}
