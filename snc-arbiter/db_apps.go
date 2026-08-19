// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// App-store schema: user-submitted, admin-moderated listings for apps.navlink.net.
// Mirrors the nodes table's submit→pending→approved workflow (see db.go), with
// 'rejected' added so an admin can send a listing back with a reason instead of
// only ever accepting or silently ignoring it.
const appsSchema = `
CREATE TABLE IF NOT EXISTS app_listings (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	owner_id       INTEGER NOT NULL REFERENCES users(id),
	name           TEXT    NOT NULL,
	description    TEXT    NOT NULL DEFAULT '',
	category       TEXT    NOT NULL DEFAULT '',
	platforms      TEXT    NOT NULL DEFAULT '',  -- comma-separated platform tags, see appPlatforms
	icon_path      TEXT    NOT NULL DEFAULT '',  -- relative path under the shared apps-assets mount
	copyright_text TEXT    NOT NULL DEFAULT '',
	privacy_text   TEXT    NOT NULL DEFAULT '',
	status         TEXT    NOT NULL DEFAULT 'pending',  -- 'pending'|'published'|'rejected'
	reject_reason  TEXT    NOT NULL DEFAULT '',
	submitted_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	published_at   INTEGER,
	updated_at     INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS app_listing_downloads (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	listing_id  INTEGER NOT NULL REFERENCES app_listings(id) ON DELETE CASCADE,
	platform    TEXT    NOT NULL,
	url         TEXT    NOT NULL DEFAULT '',  -- external download URL, or...
	file_path   TEXT    NOT NULL DEFAULT ''   -- ...an uploaded binary path under the shared mount
);

CREATE INDEX IF NOT EXISTS app_listings_status_idx ON app_listings(status);
CREATE INDEX IF NOT EXISTS app_listing_downloads_listing_idx ON app_listing_downloads(listing_id);
`

// appPlatforms is the fixed set of platform tags the submission form and OS filter
// both use — matches the icons already shipped under Web/apps/assets/icons/os-*.png.
var appPlatforms = []string{"windows", "macos", "linux", "android", "ios", "web", "docker"}

func (d *DB) initAppsSchema() error {
	if _, err := d.db.Exec(appsSchema); err != nil {
		return err
	}
	// Publisher profile fields required before a user can submit a listing —
	// see requireCompleteProfile. Not part of the original users table (db.go),
	// added here since they only matter for this feature.
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN contact   TEXT NOT NULL DEFAULT ''`,
	} {
		d.db.Exec(stmt) //nolint:errcheck // fails on duplicate column, which is fine
	}
	return d.seedInitialAppListings()
}

// seedInitialAppListings backfills the 10 hand-written cards that used to be
// hardcoded in Web/apps/index.html as real, already-published rows, so cutting
// the storefront over to dynamic rendering doesn't leave it empty on day one.
// No-op if app_listings already has any rows (including from a prior seed) —
// safe to call on every startup.
//
// Icon paths here are bare filenames (e.g. "snc-icon.png") matching the
// existing files under Web/apps/assets/ — for these to actually resolve via
// appsAssetURL, those existing PNGs need to be copied into the new shared
// mount (/mnt/remote/navlink/apps/assets/) once it's set up on the static
// host. Not done by this code; an ops step, see TODO.md's storage-location
// section.
func (d *DB) seedInitialAppListings() error {
	var count int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM app_listings`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	ownerID := d.firstAdminUserID()
	if ownerID == 0 {
		// No admin exists yet (fresh DB, nobody has logged in once) -- nothing to
		// own the seed rows. Harmless to skip; next startup after the first admin
		// exists will seed them instead, since count is still 0 then.
		return nil
	}
	type seed struct {
		name, desc, category, icon string
		platforms                  []string
		downloads                  map[string]string // platform -> url
	}
	seeds := []seed{
		{"ShortNerdCat", "Add a key, press Connect, and let ShortNerdCat choose the available route automatically.",
			"Client", "snc-icon.png",
			[]string{"windows", "macos", "linux", "android"},
			map[string]string{
				"windows": "https://navlink.net/download/zip-installer",
				"macos":   "https://navlink.net/download/dmg",
				"linux":   "https://navlink.net/download/deb",
				"android": "https://navlink.net/download/apk",
			}},
		{"Ratatosk", "Chat and calls that run on top of the Tunnel Cat network, built for unstable and restricted connections.",
			"Messenger", "ratatosk-icon.png",
			[]string{"web", "android", "windows"},
			map[string]string{
				"web":     "https://ratatosk.navlink.net",
				"android": "https://navlink.net/ratatosk/download/apk",
				"windows": "https://navlink.net/ratatosk/download/zip",
			}},
		{"Proekt", "The Proekt publication app for reading articles through the Tunnel Cat network.",
			"Media application", "proekt-icon.png",
			[]string{"android"},
			map[string]string{"android": "https://navlink.net/partners/download/apk"}},
		{"Lisinder", "News, publications, and experimental Radio Lisinder, delivered through the Tunnel Cat network.",
			"News and radio", "lisinder-icon.png",
			[]string{"android", "web"},
			map[string]string{
				"android": "https://navlink.net/partners/lisinder/download/apk",
				"web":     "https://lisinder.partners.solutions",
			}},
		{"BlackBadger", "A containerized client for services and teams that need network access without a separate GUI application.",
			"Infrastructure client", "blackbadger-icon.png",
			[]string{"docker"},
			map[string]string{"docker": "https://navlink.net/blackbadger"}},
	}
	for _, s := range seeds {
		var downloads []AppListingDownload
		for _, p := range s.platforms {
			downloads = append(downloads, AppListingDownload{Platform: p, URL: s.downloads[p]})
		}
		id, err := d.submitAppListing(ownerID, s.name, s.desc, s.category, s.platforms,
			s.icon, defaultAppCopyright, defaultAppPrivacy, downloads)
		if err != nil {
			return fmt.Errorf("seed %s: %w", s.name, err)
		}
		if err := d.approveAppListing(id); err != nil {
			return fmt.Errorf("seed publish %s: %w", s.name, err)
		}
	}
	return nil
}

// AppListing is one row from app_listings, plus its per-platform downloads.
type AppListing struct {
	ID            int64
	OwnerID       int64
	OwnerUsername string
	Name          string
	Description   string
	Category      string
	Platforms     []string
	IconPath      string
	CopyrightText string
	PrivacyText   string
	Status        string // "pending" | "published" | "rejected"
	RejectReason  string
	SubmittedAt   time.Time
	PublishedAt   *time.Time
	UpdatedAt     time.Time
	Downloads     []AppListingDownload
}

// AppListingDownload is one platform's download target for a listing — either an
// external URL (e.g. a linked web app, or a third-party store page) or a path to a
// binary uploaded through the admin/submission form.
type AppListingDownload struct {
	ID       int64
	Platform string
	URL      string
	FilePath string
}

const appListingCols = `
	l.id, l.owner_id, u.username, l.name, l.description, l.category, l.platforms,
	l.icon_path, l.copyright_text, l.privacy_text, l.status, l.reject_reason,
	l.submitted_at, l.published_at, l.updated_at`

func scanAppListing(row interface {
	Scan(dest ...interface{}) error
}) (*AppListing, error) {
	var l AppListing
	var platformsCSV string
	var submittedAt, updatedAt int64
	var publishedAt sql.NullInt64
	if err := row.Scan(
		&l.ID, &l.OwnerID, &l.OwnerUsername, &l.Name, &l.Description, &l.Category,
		&platformsCSV, &l.IconPath, &l.CopyrightText, &l.PrivacyText, &l.Status,
		&l.RejectReason, &submittedAt, &publishedAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	l.Platforms = splitCSV(platformsCSV)
	l.SubmittedAt = time.Unix(submittedAt, 0)
	l.UpdatedAt = time.Unix(updatedAt, 0)
	if publishedAt.Valid {
		t := time.Unix(publishedAt.Int64, 0)
		l.PublishedAt = &t
	}
	return &l, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// submitAppListing inserts a new listing in "pending" status — visible to the admin
// moderation queue, not yet public. downloads is written in the same call so a
// listing never exists without at least its submitted platform targets.
func (d *DB) submitAppListing(ownerID int64, name, description, category string, platforms []string,
	iconPath, copyrightText, privacyText string, downloads []AppListingDownload) (int64, error) {
	// RETURNING id, not res.LastInsertId(): the Postgres driver doesn't
	// implement LastInsertId at all, and the error was being silently
	// discarded here -- meaning id came back 0 on Postgres and
	// replaceAppListingDownloads below was writing every submission's
	// downloads against a nonexistent app_id=0 instead of erroring loudly.
	var id int64
	err := d.db.QueryRow(`
		INSERT INTO app_listings (owner_id, name, description, category, platforms, icon_path, copyright_text, privacy_text)
		VALUES (?,?,?,?,?,?,?,?) RETURNING id`,
		ownerID, name, description, category, strings.Join(platforms, ","), iconPath, copyrightText, privacyText).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("submit app listing: %w", err)
	}
	if err := d.replaceAppListingDownloads(id, downloads); err != nil {
		return id, fmt.Errorf("submit app listing downloads: %w", err)
	}
	return id, nil
}

// updateAppListing overwrites an existing listing's editable fields and downloads,
// and resets it to "pending" so an edit after rejection (or after publishing) goes
// back through moderation rather than silently changing a live listing.
func (d *DB) updateAppListing(id int64, name, description, category string, platforms []string,
	iconPath, copyrightText, privacyText string, downloads []AppListingDownload) error {
	_, err := d.db.Exec(`
		UPDATE app_listings
		SET name=?, description=?, category=?, platforms=?, icon_path=?, copyright_text=?, privacy_text=?,
		    status='pending', reject_reason='', updated_at=strftime('%s','now')
		WHERE id=?`,
		name, description, category, strings.Join(platforms, ","), iconPath, copyrightText, privacyText, id)
	if err != nil {
		return fmt.Errorf("update app listing: %w", err)
	}
	return d.replaceAppListingDownloads(id, downloads)
}

func (d *DB) replaceAppListingDownloads(listingID int64, downloads []AppListingDownload) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`DELETE FROM app_listing_downloads WHERE listing_id=?`, listingID); err != nil {
		return err
	}
	for _, dl := range downloads {
		if dl.Platform == "" || (dl.URL == "" && dl.FilePath == "") {
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO app_listing_downloads (listing_id, platform, url, file_path) VALUES (?,?,?,?)`,
			listingID, dl.Platform, dl.URL, dl.FilePath); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) getAppListingDownloads(listingID int64) ([]AppListingDownload, error) {
	rows, err := d.db.Query(
		`SELECT id, platform, url, file_path FROM app_listing_downloads WHERE listing_id=? ORDER BY id ASC`,
		listingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppListingDownload
	for rows.Next() {
		var dl AppListingDownload
		if err := rows.Scan(&dl.ID, &dl.Platform, &dl.URL, &dl.FilePath); err != nil {
			return nil, err
		}
		out = append(out, dl)
	}
	return out, rows.Err()
}

// getAppListing returns one listing (any status) with its downloads populated, or
// nil if it doesn't exist. Callers decide whether the caller is allowed to see a
// non-published listing (owner or admin only) — this function itself has no ACL.
func (d *DB) getAppListing(id int64) (*AppListing, error) {
	row := d.db.QueryRow(`
		SELECT `+appListingCols+`
		FROM app_listings l JOIN users u ON u.id = l.owner_id
		WHERE l.id=?`, id)
	l, err := scanAppListing(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dls, err := d.getAppListingDownloads(id)
	if err != nil {
		return nil, err
	}
	l.Downloads = dls
	return l, nil
}

// listPublishedAppListings returns published listings, optionally filtered by a
// search term (matches name/description, case-insensitive substring) and/or a
// single platform tag. Both filters are ANDed; empty string skips that filter.
func (d *DB) listPublishedAppListings(query, platform string) ([]AppListing, error) {
	sqlq := `
		SELECT ` + appListingCols + `
		FROM app_listings l JOIN users u ON u.id = l.owner_id
		WHERE l.status='published'`
	var args []interface{}
	if query != "" {
		sqlq += ` AND (l.name LIKE ? OR l.description LIKE ?)`
		like := "%" + query + "%"
		args = append(args, like, like)
	}
	if platform != "" {
		sqlq += ` AND (',' || l.platforms || ',') LIKE ?`
		args = append(args, "%,"+platform+",%")
	}
	sqlq += ` ORDER BY l.published_at DESC`
	rows, err := d.db.Query(sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAppListingRows(rows, d)
}

// listPendingAppListings returns listings awaiting admin review, oldest first.
func (d *DB) listPendingAppListings() ([]AppListing, error) {
	rows, err := d.db.Query(`
		SELECT ` + appListingCols + `
		FROM app_listings l JOIN users u ON u.id = l.owner_id
		WHERE l.status='pending' ORDER BY l.submitted_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAppListingRows(rows, d)
}

// listAppListingsByOwner returns every listing (any status) a user has submitted,
// newest first — powers a "my submissions" view.
func (d *DB) listAppListingsByOwner(ownerID int64) ([]AppListing, error) {
	rows, err := d.db.Query(`
		SELECT `+appListingCols+`
		FROM app_listings l JOIN users u ON u.id = l.owner_id
		WHERE l.owner_id=? ORDER BY l.id DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAppListingRows(rows, d)
}

// listAllAppListings returns every listing regardless of status, for the admin panel.
func (d *DB) listAllAppListings() ([]AppListing, error) {
	rows, err := d.db.Query(`
		SELECT ` + appListingCols + `
		FROM app_listings l JOIN users u ON u.id = l.owner_id
		ORDER BY l.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAppListingRows(rows, d)
}

func scanAppListingRows(rows *sql.Rows, d *DB) ([]AppListing, error) {
	var out []AppListing
	var ids []int64
	for rows.Next() {
		l, err := scanAppListing(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
		ids = append(ids, l.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Downloads are fetched per-row after the main query completes rather than
	// inline in the loop -- sqlite's single-writer/single-statement-at-a-time
	// driver here can't run a second query while the first's rows are still open.
	for i := range out {
		dls, err := d.getAppListingDownloads(ids[i])
		if err != nil {
			return nil, err
		}
		out[i].Downloads = dls
	}
	return out, nil
}

func (d *DB) approveAppListing(id int64) error {
	res, err := d.db.Exec(`
		UPDATE app_listings SET status='published', published_at=strftime('%s','now'), reject_reason=''
		WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("app listing %d not found", id)
	}
	return nil
}

func (d *DB) rejectAppListing(id int64, reason string) error {
	res, err := d.db.Exec(`
		UPDATE app_listings SET status='rejected', reject_reason=?, updated_at=strftime('%s','now')
		WHERE id=?`, reason, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("app listing %d not found", id)
	}
	return nil
}

func (d *DB) deleteAppListing(id int64) error {
	_, err := d.db.Exec(`DELETE FROM app_listings WHERE id=?`, id) // downloads cascade
	return err
}

// ── publisher profile ────────────────────────────────────────────────────────

// isProfileComplete reports whether a user has filled in the full name + contact
// fields required to submit an app listing (see the app-store publishing model:
// submission is tied to a real, identifiable NavLink account, not free text).
func (d *DB) isProfileComplete(userID int64) (bool, error) {
	var fullName, contact string
	err := d.db.QueryRow(`SELECT full_name, contact FROM users WHERE id=?`, userID).Scan(&fullName, &contact)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(fullName) != "" && strings.TrimSpace(contact) != "", nil
}

func (d *DB) setUserProfile(userID int64, fullName, contact string) error {
	_, err := d.db.Exec(`UPDATE users SET full_name=?, contact=? WHERE id=?`, fullName, contact, userID)
	return err
}

func (d *DB) getUserProfile(userID int64) (fullName, contact string, err error) {
	err = d.db.QueryRow(`SELECT full_name, contact FROM users WHERE id=?`, userID).Scan(&fullName, &contact)
	return
}
