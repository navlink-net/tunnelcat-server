// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

// rebindingDB wraps *sqlx.DB and transparently rebinds "?"-style SQL
// placeholders to whatever the underlying driver actually needs (a no-op
// for SQLite, which already uses "?"; "$1, $2, ..." for Postgres) on every
// Query/Exec/QueryRow/Begin call -- this is what lets every one of the
// ~280 existing call sites across the package keep writing SQLite-style
// placeholders completely unchanged, working against either engine
// depending on which one openDB actually opened. Both DB.db (db.go) and
// openPostgresDB (db_postgres.go) construct one of these instead of using
// the bare *sqlx.DB directly.
//
// Discovered as a real, not theoretical, gap: the first end-to-end test
// against real Postgres (db_postgres_smoke_test.go) failed on the very
// first query with a Postgres syntax error, because nothing was rebinding
// "?" to "$1" yet -- confirmed this wrapper fixes it, not just assumed.
type rebindingDB struct{ *sqlx.DB }

func (r *rebindingDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return r.DB.Query(r.Rebind(query), args...)
}

func (r *rebindingDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return r.DB.Exec(r.Rebind(query), args...)
}

func (r *rebindingDB) QueryRow(query string, args ...interface{}) *sql.Row {
	return r.DB.QueryRow(r.Rebind(query), args...)
}

// Begin shadows the promoted *sql.DB.Begin so every transaction-scoped
// call site (tx.Query/tx.Exec/tx.QueryRow) gets the same rebinding
// treatment -- without this, a transaction opened via d.db.Begin() would
// silently fall back to the raw, non-rebinding *sql.Tx methods.
func (r *rebindingDB) Begin() (*rebindingTx, error) {
	tx, err := r.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &rebindingTx{Tx: tx, bindType: r.DB}, nil
}

// rebindingTx is the transaction-scoped counterpart to rebindingDB. A
// *sql.Tx has no Rebind method of its own (it doesn't know the driver
// bindtype), so bindType keeps a reference to the parent *sqlx.DB purely
// to reuse its Rebind logic.
type rebindingTx struct {
	*sql.Tx
	bindType *sqlx.DB
}

func (t *rebindingTx) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return t.Tx.Query(t.bindType.Rebind(query), args...)
}

func (t *rebindingTx) Exec(query string, args ...interface{}) (sql.Result, error) {
	return t.Tx.Exec(t.bindType.Rebind(query), args...)
}

func (t *rebindingTx) QueryRow(query string, args ...interface{}) *sql.Row {
	return t.Tx.QueryRow(t.bindType.Rebind(query), args...)
}
