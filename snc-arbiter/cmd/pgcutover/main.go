// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// pgcutover is a one-off tool for the SQLite -> Postgres cutover (Phase 7
// of the arbiter persistence migration). Not part of the snc-arbiter
// binary itself -- built and run once, on the arbiter box, against the
// now-quiesced SQLite file and the already-migrated Postgres schema.
//
// Usage: pgcutover <sqlite-path> <postgres-dsn>
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// tables lists every table in FK-dependency order (parents before
// children) so inserts never violate a foreign key. Matches
// snc-arbiter/migrations/postgres/00001_initial_schema.sql exactly.
var tables = []string{
	"users",
	"clubs",
	"nodes",
	"whitelist_entries", "anon_allowlist_entries", "service_region_blocks",
	"blacklist_entries", "torrent_blocked_entries", "excluded_nodes",
	"user_confirmations", "email_tokens", "sessions",
	"subscription_plans", "system_settings",
	"keys", "subscriptions",
	"promo_codes", "promo_uses",
	"notifications",
	"node_traffic", "node_counter_state",
	"app_listings", "app_listing_downloads",
	"bananameter_results",
	"club_membership_events",
	"client_conn_stats",
	"user_stats",
	"network_usage_stats",
	"session_durations",
}

// identityTables have a BIGINT GENERATED ALWAYS AS IDENTITY "id" primary
// key -- Postgres rejects an explicit value for that column unless the
// INSERT carries OVERRIDING SYSTEM VALUE, since preserving the exact
// original ids (referenced by every FK) matters here.
var identityTables = map[string]bool{
	"users": true, "nodes": true,
	"whitelist_entries": true, "anon_allowlist_entries": true, "service_region_blocks": true,
	"blacklist_entries": true, "torrent_blocked_entries": true, "excluded_nodes": true,
	"promo_uses": true, "app_listings": true, "app_listing_downloads": true,
	"bananameter_results": true, "clubs": true, "club_membership_events": true,
	"session_durations": true, "client_conn_stats": true,
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: pgcutover <sqlite-path> <postgres-dsn>")
		os.Exit(1)
	}
	sqlitePath, pgDSN := os.Args[1], os.Args[2]

	sq, err := sql.Open("sqlite", sqlitePath+"?_timeout=5000")
	must(err, "open sqlite")
	defer sq.Close()

	pg, err := sql.Open("pgx", pgDSN)
	must(err, "open postgres")
	defer pg.Close()
	must(pg.Ping(), "ping postgres")

	// Defer FK/constraint checking until commit, and let identity columns
	// accept explicit values table-wide without repeating OVERRIDING
	// SYSTEM VALUE logic per-row -- session_replication_role=replica also
	// disables triggers, which is fine here since there are none relevant
	// to plain data load.
	must(exec(pg, "SET session_replication_role = replica"), "set replica mode")

	totalRows := 0
	for _, table := range tables {
		n, err := migrateTable(sq, pg, table)
		must(err, "migrate "+table)
		fmt.Printf("%-28s %8d rows\n", table, n)
		totalRows += n
	}

	must(exec(pg, "SET session_replication_role = default"), "restore replication role")

	must(resetSequences(pg), "reset identity sequences")

	fmt.Printf("\ntotal: %d rows across %d tables\n\n", totalRows, len(tables))

	fmt.Println("=== verification: row counts (sqlite vs postgres) ===")
	mismatches := 0
	for _, table := range tables {
		sc, err := countRows(sq, table)
		must(err, "count sqlite "+table)
		pc, err := countRows(pg, table)
		must(err, "count postgres "+table)
		status := "OK"
		if sc != pc {
			status = "MISMATCH"
			mismatches++
		}
		fmt.Printf("%-28s sqlite=%-8d postgres=%-8d %s\n", table, sc, pc, status)
	}
	if mismatches > 0 {
		log.Fatalf("\n%d table(s) have row-count mismatches -- DO NOT proceed with cutover", mismatches)
	}
	fmt.Println("\nall row counts match.")
}

func migrateTable(sq, pg *sql.DB, table string) (int, error) {
	rows, err := sq.Query("SELECT * FROM " + table)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}

	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	overriding := ""
	if identityTables[table] {
		overriding = "OVERRIDING SYSTEM VALUE "
	}
	insertSQL := fmt.Sprintf(`INSERT INTO %s (%s) %sVALUES (%s)`,
		table, quoteCols(cols), overriding, strings.Join(placeholders, ","))

	tx, err := pg.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		return 0, fmt.Errorf("prepare %q: %w", insertSQL, err)
	}
	defer stmt.Close()

	n := 0
	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		sanitizeNULs(table, cols, vals)
		if _, err := stmt.Exec(vals...); err != nil {
			return n, fmt.Errorf("insert row %d into %s: %w", n+1, table, err)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	return n, tx.Commit()
}

// quoteCols quotes every column name -- "offset" (node_counter_state) is a
// Postgres reserved word and needs it; harmless for every other column.
func quoteCols(cols []string) string {
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = `"` + c + `"`
	}
	return strings.Join(quoted, ",")
}

// sanitizeNULs cleans TEXT-typed values in place so they're acceptable to
// Postgres's text type, which (unlike SQLite's untyped TEXT storage) (a)
// rejects any embedded NUL byte outright regardless of UTF-8 validity, and
// (b) requires valid UTF-8. Two real, distinct production data issues
// found during the cutover dry run, not hypothetical:
//   - node 37's deploy_log (captured raw output of a failed deploy
//     attempt) contains hundreds of literal NUL bytes -- presumably
//     corrupted terminal output.
//   - a service_region_blocks row contains a raw 0x97 byte -- looks like
//     Windows-1252 text (0x97 is an em-dash in that encoding) that was
//     never actually converted to UTF-8 when originally inserted.
// SQLite's TEXT columns don't enforce either constraint, so this data has
// been sitting there harmlessly until now. Only `string`-typed scanned
// values are touched -- []byte values are BLOB columns
// (sessions.enc_password is the only one) and must be preserved exactly;
// Postgres's bytea type has neither restriction, so there's nothing to
// sanitize there.
func sanitizeNULs(table string, cols []string, vals []interface{}) {
	for i, v := range vals {
		// enc_password (sessions) is the only BLOB/bytea column in the
		// whole schema, declared NOT NULL, with an established
		// zero-length-means-"no password" convention (LoginWithKey's
		// key-auth sessions). modernc.org/sqlite's generic interface{}
		// scan collapses a zero-length BLOB to a Go nil []byte, which the
		// pgx driver then sends as SQL NULL, not an empty bytea --
		// violating the NOT NULL constraint (a real failure hit during
		// the dry run, affecting ~2300 key-auth session rows). Since this
		// is the only []byte-typed column that exists, it's unambiguous
		// to normalize nil -> empty here.
		if b, ok := v.([]byte); ok && b == nil {
			vals[i] = []byte{}
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		// A one-off found during the dry run: system_settings.admin_api_token's
		// updated_at holds the literal string "2026-04-21 19:57:40" instead
		// of a Unix-epoch integer -- SQLite's loose type affinity let some
		// past manual edit (a raw sqlite3 UPDATE, presumably using
		// datetime('now') instead of strftime('%s','now')) write a
		// human-readable timestamp into what every other row in this same
		// column correctly stores as an epoch int. Convert it rather than
		// erroring out or dropping it -- it's the last-changed timestamp
		// for an otherwise-fine value, low-stakes, but worth preserving
		// its actual meaning instead of losing the date.
		if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
			fmt.Printf("NOTE: converted %s.%s datetime string %q -> epoch %d\n", table, cols[i], s, t.Unix())
			vals[i] = fmt.Sprintf("%d", t.Unix())
			continue
		}
		cleaned := strings.ReplaceAll(s, "\x00", "")
		cleaned = strings.ToValidUTF8(cleaned, "�")
		if cleaned == s {
			continue
		}
		fmt.Printf("NOTE: sanitized %s.%s (%d -> %d bytes: stripped NULs / replaced invalid UTF-8)\n",
			table, cols[i], len(s), len(cleaned))
		vals[i] = cleaned
	}
}

func countRows(db *sql.DB, table string) (int, error) {
	var n int
	err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n)
	return n, err
}

// resetSequences moves every identity table's sequence past the max id
// actually loaded, so the next INSERT (a real new row, post-cutover)
// doesn't collide with an id that was just explicitly loaded via
// OVERRIDING SYSTEM VALUE.
func resetSequences(pg *sql.DB) error {
	for table := range identityTables {
		q := fmt.Sprintf(
			`SELECT setval(pg_get_serial_sequence('%s','id'), COALESCE((SELECT MAX(id) FROM %s), 1), (SELECT MAX(id) IS NOT NULL FROM %s))`,
			table, table, table)
		if _, err := pg.Exec(q); err != nil {
			return fmt.Errorf("reset sequence for %s: %w", table, err)
		}
	}
	return nil
}

func exec(db *sql.DB, q string) error {
	_, err := db.Exec(q)
	return err
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
