-- +goose Up
-- Initial PostgreSQL schema for snc-arbiter, authored as part of the
-- SQLite -> PostgreSQL migration (see plan: "Arbiter persistence migration").
--
-- This is a single consolidated migration rather than one file per legacy
-- init*Schema() function (the original plan's suggested split) -- for a
-- fresh target database created once at cutover, a single well-organized
-- baseline achieves the same goal (a real, versioned starting point) with
-- less mechanical file-splitting. Section headers below mirror the
-- original Go-side grouping for anyone cross-referencing db.go/db_*.go.
--
-- Every table here reflects the FINAL column set as of this migration's
-- authoring date -- the 46 "ALTER TABLE ADD COLUMN" migrations scattered
-- through the old SQLite openDB() are already folded in, not replayed.
--
-- Translation notes (see plan's "Design decisions" section for the full
-- reasoning):
--   - INTEGER PRIMARY KEY AUTOINCREMENT -> BIGINT GENERATED ALWAYS AS IDENTITY
--   - REAL -> DOUBLE PRECISION, BLOB -> BYTEA
--   - Every SQLite INTEGER (including 0/1 "boolean" columns and Unix-epoch
--     timestamp columns) stays BIGINT, not converted to native BOOLEAN or
--     TIMESTAMPTZ -- preserves byte-for-byte Go-side scan compatibility,
--     nothing here forces a change to how the application code reads rows.
--   - strftime('%s','now') DEFAULT -> EXTRACT(EPOCH FROM now())::bigint
--   - "offset" (node_counter_state) is a Postgres reserved word -- quoted.

-- ── users / nodes (core/db.go) ──────────────────────────────────────────────

CREATE TABLE users (
    id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username  TEXT    NOT NULL UNIQUE,
    role      TEXT    NOT NULL DEFAULT 'user',
    client_id TEXT    NOT NULL DEFAULT '',
    user_enabled BIGINT NOT NULL DEFAULT 1,
    full_name TEXT    NOT NULL DEFAULT '',
    contact   TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE nodes (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id             BIGINT NOT NULL REFERENCES users(id),
    type                 TEXT    NOT NULL,
    addr                 TEXT    NOT NULL,
    fingerprint          TEXT    NOT NULL DEFAULT '',
    pubkey               TEXT    NOT NULL DEFAULT '',
    description          TEXT    NOT NULL DEFAULT '',
    token                TEXT    UNIQUE,
    status               TEXT    NOT NULL DEFAULT 'pending',
    submitted_at         BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
    approved_at          BIGINT,
    last_heartbeat       BIGINT,
    rtt_ms               DOUBLE PRECISION NOT NULL DEFAULT 0,
    load                 DOUBLE PRECISION NOT NULL DEFAULT 0,
    bandwidth_mbps       DOUBLE PRECISION NOT NULL DEFAULT 0,
    data_plane_ok        BIGINT,
    sni_list             TEXT    NOT NULL DEFAULT '',
    ssh_host             TEXT    NOT NULL DEFAULT '',
    deploy_status        TEXT    NOT NULL DEFAULT '',
    deploy_log           TEXT    NOT NULL DEFAULT '',
    ssh_user             TEXT    NOT NULL DEFAULT 'root',
    region_override      TEXT    NOT NULL DEFAULT '',
    capabilities         TEXT    NOT NULL DEFAULT '',
    location             TEXT    NOT NULL DEFAULT '',
    provider             TEXT    NOT NULL DEFAULT '',
    pinned               BIGINT NOT NULL DEFAULT 0,
    node_uid             TEXT,
    provider_slug        TEXT,
    provider_instance_id TEXT,
    club_id              BIGINT
);
CREATE UNIQUE INDEX idx_nodes_uid ON nodes(node_uid) WHERE node_uid IS NOT NULL;
CREATE UNIQUE INDEX idx_nodes_provider_instance ON nodes(provider_slug, provider_instance_id)
    WHERE provider_slug IS NOT NULL AND provider_instance_id IS NOT NULL;

-- ── policy lists (whitelist/blacklist/region-blocks/etc, core/db.go) ───────

CREATE TABLE whitelist_entries (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type       TEXT    NOT NULL CHECK(type IN ('domain','wildcard','cidr')),
    value      TEXT    NOT NULL UNIQUE,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

CREATE TABLE anon_allowlist_entries (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type       TEXT    NOT NULL CHECK(type IN ('domain','wildcard','cidr')),
    value      TEXT    NOT NULL UNIQUE,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

CREATE TABLE service_region_blocks (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type            TEXT    NOT NULL CHECK(type IN ('domain','wildcard','cidr')),
    value           TEXT    NOT NULL,
    blocked_regions TEXT    NOT NULL,
    reason          TEXT    NOT NULL DEFAULT '',
    created_at      BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

CREATE TABLE blacklist_entries (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    addr       TEXT    NOT NULL UNIQUE,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

CREATE TABLE torrent_blocked_entries (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    addr       TEXT    NOT NULL UNIQUE,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

CREATE TABLE excluded_nodes (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    addr       TEXT    NOT NULL UNIQUE,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

-- ── auth / sessions (core/db.go) ────────────────────────────────────────────

CREATE TABLE user_confirmations (
    username   TEXT    PRIMARY KEY,
    confirmed  BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
    source     TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE email_tokens (
    token      TEXT    PRIMARY KEY,
    username   TEXT    NOT NULL,
    type       TEXT    NOT NULL CHECK(type IN ('confirm','reset')),
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

CREATE TABLE sessions (
    token        TEXT    PRIMARY KEY,
    username     TEXT    NOT NULL,
    client_id    TEXT    NOT NULL DEFAULT '',
    device_id    TEXT    NOT NULL DEFAULT '',
    device_name  TEXT    NOT NULL DEFAULT '',
    enc_password BYTEA   NOT NULL,
    cam_session  TEXT    NOT NULL DEFAULT '',
    validated_at BIGINT NOT NULL DEFAULT 0,
    last_attempt BIGINT NOT NULL DEFAULT 0
);

-- ── billing (core/db.go + db_keys.go) ───────────────────────────────────────

CREATE TABLE subscription_plans (
    region        TEXT    NOT NULL,
    duration_days BIGINT NOT NULL DEFAULT 30,
    price_pia     BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
    updated_by    TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (region, duration_days)
);

CREATE TABLE system_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
    updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE keys (
    key_id                  TEXT PRIMARY KEY,
    username                TEXT NOT NULL,
    device_id               TEXT,
    device_name             TEXT,
    enabled                 BIGINT NOT NULL DEFAULT 1,
    issued_at               BIGINT NOT NULL DEFAULT 0,
    bound_at                BIGINT NOT NULL DEFAULT 0,
    last_seen               BIGINT NOT NULL DEFAULT 0,
    warn_count              BIGINT NOT NULL DEFAULT 0,
    last_warned_at          BIGINT NOT NULL DEFAULT 0,
    paid_until              BIGINT,
    plan_pia                BIGINT NOT NULL DEFAULT 0,
    reminder_sent           BIGINT NOT NULL DEFAULT 0,
    preferred_duration_days BIGINT NOT NULL DEFAULT 30,
    unlimited_devices       BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX keys_username ON keys(username);

CREATE TABLE subscriptions (
    key_id          TEXT    PRIMARY KEY REFERENCES keys(key_id) ON DELETE CASCADE,
    client_id       TEXT    NOT NULL DEFAULT '',
    user_email      TEXT    NOT NULL,
    plan_pia        BIGINT NOT NULL,
    paid_until      BIGINT NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'active',
    last_charged_at BIGINT,
    created_at      BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

CREATE TABLE promo_codes (
    code                  TEXT    PRIMARY KEY,
    type                  TEXT    NOT NULL DEFAULT 'free',
    discount_val          DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_uses              BIGINT NOT NULL DEFAULT 0,
    uses                  BIGINT NOT NULL DEFAULT 0,
    per_user              BIGINT NOT NULL DEFAULT 1,
    valid_from            BIGINT NOT NULL DEFAULT 0,
    valid_until           BIGINT NOT NULL DEFAULT 0,
    enabled               BIGINT NOT NULL DEFAULT 1,
    description           TEXT    NOT NULL DEFAULT '',
    created_at            BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
    created_by            TEXT    NOT NULL DEFAULT '',
    allowed_duration_days BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE promo_uses (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code        TEXT    NOT NULL,
    username    TEXT    NOT NULL,
    used_at     BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
    key_id      TEXT    NOT NULL DEFAULT '',
    charged_pia BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX promo_uses_code_user ON promo_uses(code, username);

-- ── notifications / wlwtp (core/db.go) ──────────────────────────────────────

CREATE TABLE notifications (
    id         TEXT    PRIMARY KEY,
    message    TEXT    NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
    created_by TEXT    NOT NULL DEFAULT '',
    username   TEXT
);

CREATE TABLE wlwtp_ports (
    ctrl_addr  TEXT    PRIMARY KEY,
    ports      TEXT    NOT NULL DEFAULT '',
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);

-- ── node traffic/stats (db.go trafficSchemaSQL) ─────────────────────────────

CREATE TABLE node_traffic (
    node_id        BIGINT NOT NULL,
    ts             BIGINT NOT NULL,
    bytes_total    BIGINT NOT NULL DEFAULT 0,
    bw_mbps        DOUBLE PRECISION NOT NULL DEFAULT 0,
    rtt_ms         DOUBLE PRECISION NOT NULL DEFAULT 0,
    cpu_pct        DOUBLE PRECISION NOT NULL DEFAULT 0,
    mem_pct        DOUBLE PRECISION NOT NULL DEFAULT 0,
    disk_pct       DOUBLE PRECISION NOT NULL DEFAULT 0,
    bytes_cum      BIGINT NOT NULL DEFAULT 0,
    routing_rtt_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
    node_type      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX node_traffic_node_ts ON node_traffic(node_id, ts);

CREATE TABLE node_counter_state (
    node_id  BIGINT PRIMARY KEY,
    "offset" BIGINT NOT NULL DEFAULT 0,
    last_raw BIGINT NOT NULL DEFAULT 0
);

-- ── apps store (db_apps.go) ─────────────────────────────────────────────────

CREATE TABLE app_listings (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id       BIGINT NOT NULL REFERENCES users(id),
    name           TEXT    NOT NULL,
    description    TEXT    NOT NULL DEFAULT '',
    category       TEXT    NOT NULL DEFAULT '',
    platforms      TEXT    NOT NULL DEFAULT '',
    icon_path      TEXT    NOT NULL DEFAULT '',
    copyright_text TEXT    NOT NULL DEFAULT '',
    privacy_text   TEXT    NOT NULL DEFAULT '',
    status         TEXT    NOT NULL DEFAULT 'pending',
    reject_reason  TEXT    NOT NULL DEFAULT '',
    submitted_at   BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
    published_at   BIGINT,
    updated_at     BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);
CREATE TABLE app_listing_downloads (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    listing_id BIGINT NOT NULL REFERENCES app_listings(id) ON DELETE CASCADE,
    platform   TEXT    NOT NULL,
    url        TEXT    NOT NULL DEFAULT '',
    file_path  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX app_listings_status_idx ON app_listings(status);
CREATE INDEX app_listing_downloads_listing_idx ON app_listing_downloads(listing_id);

-- ── bananameter (db_bananameter.go) ─────────────────────────────────────────

CREATE TABLE bananameter_results (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_type      TEXT    NOT NULL,
    source_id        TEXT    NOT NULL,
    username         TEXT    NOT NULL DEFAULT '',
    device_id        TEXT    NOT NULL DEFAULT '',
    via_exit         TEXT    NOT NULL DEFAULT '',
    ts               BIGINT NOT NULL,
    duration_seconds DOUBLE PRECISION NOT NULL,
    payload_bytes    BIGINT NOT NULL,
    ping_ms          DOUBLE PRECISION NOT NULL DEFAULT 0,
    throughput_bps   DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX idx_bananameter_source_ts ON bananameter_results(source_type, source_id, ts);
CREATE INDEX idx_bananameter_ts ON bananameter_results(ts);

-- ── clubs (db_clubs.go) ──────────────────────────────────────────────────────

CREATE TABLE clubs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    slug                TEXT    NOT NULL UNIQUE,
    name                TEXT    NOT NULL,
    rec_threshold_cat   BIGINT NOT NULL DEFAULT 0,
    rec_threshold_elite BIGINT NOT NULL DEFAULT 0,
    subsumes_club_id    BIGINT REFERENCES clubs(id),
    manifest_key        TEXT    NOT NULL DEFAULT '',
    created_at          BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);
CREATE TABLE club_membership_events (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    club_id           BIGINT NOT NULL REFERENCES clubs(id),
    target_user       BIGINT NOT NULL REFERENCES users(id),
    kind              TEXT    NOT NULL CHECK(kind IN ('invite','recommendation','granted','revoked')),
    actor_user        BIGINT REFERENCES users(id),
    membership_number BIGINT,
    created_at        BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint)
);
CREATE INDEX club_membership_events_target_idx ON club_membership_events(club_id, target_user);
CREATE INDEX club_membership_events_actor_idx ON club_membership_events(club_id, actor_user);
ALTER TABLE nodes ADD CONSTRAINT nodes_club_id_fkey FOREIGN KEY (club_id) REFERENCES clubs(id);

-- ── connection stats (db_conn_stats.go) ─────────────────────────────────────

CREATE TABLE client_conn_stats (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts                   BIGINT NOT NULL,
    username             TEXT    NOT NULL,
    device_id            TEXT    NOT NULL DEFAULT '',
    node_type            TEXT    NOT NULL DEFAULT '',
    client_version       TEXT    NOT NULL DEFAULT '',
    pool_tcp             BIGINT NOT NULL DEFAULT 0,
    pool_udp             BIGINT NOT NULL DEFAULT 0,
    unreachable_controls BIGINT NOT NULL DEFAULT 0,
    total_controls       BIGINT NOT NULL DEFAULT 0,
    seconds_online       BIGINT NOT NULL DEFAULT 0,
    avg_fail_ratio       DOUBLE PRECISION NOT NULL DEFAULT 0,
    rejected_sessions    BIGINT NOT NULL DEFAULT 0,
    connects_manual      BIGINT NOT NULL DEFAULT 0,
    connects_auto        BIGINT NOT NULL DEFAULT 0,
    disconnects_manual   BIGINT NOT NULL DEFAULT 0,
    disconnects_auto     BIGINT NOT NULL DEFAULT 0,
    flap_events          BIGINT NOT NULL DEFAULT 0,
    evictions            BIGINT NOT NULL DEFAULT 0,
    wildcat_sessions     BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX client_conn_stats_username_ts ON client_conn_stats(username, ts);
CREATE INDEX client_conn_stats_ts ON client_conn_stats(ts);

-- ── login/auth stats (db_stats.go) ──────────────────────────────────────────

CREATE TABLE user_stats (
    username   TEXT    PRIMARY KEY,
    first_seen BIGINT NOT NULL DEFAULT 0,
    last_seen  BIGINT NOT NULL DEFAULT 0,
    bytes_up   BIGINT NOT NULL DEFAULT 0,
    bytes_down BIGINT NOT NULL DEFAULT 0,
    country    TEXT    NOT NULL DEFAULT '',
    conns      BIGINT NOT NULL DEFAULT 0
);
-- ── network usage (usage_stats.go) ──────────────────────────────────────────

CREATE TABLE network_usage_stats (
    ts           BIGINT PRIMARY KEY,
    active_users BIGINT NOT NULL DEFAULT 0,
    bytes_total  BIGINT NOT NULL DEFAULT 0
);

-- ── session durations (db_sessions.go) ──────────────────────────────────────

CREATE TABLE session_durations (
    id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT    NOT NULL,
    node_id  BIGINT NOT NULL DEFAULT 0,
    seconds  BIGINT NOT NULL DEFAULT 0,
    ended_at BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX session_durations_ended_at ON session_durations(ended_at);

-- +goose Down
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS nodes_club_id_fkey;
DROP TABLE IF EXISTS session_durations;
DROP TABLE IF EXISTS network_usage_stats;
DROP TABLE IF EXISTS user_stats;
DROP TABLE IF EXISTS client_conn_stats;
DROP TABLE IF EXISTS club_membership_events;
DROP TABLE IF EXISTS clubs;
DROP TABLE IF EXISTS bananameter_results;
DROP TABLE IF EXISTS app_listing_downloads;
DROP TABLE IF EXISTS app_listings;
DROP TABLE IF EXISTS node_counter_state;
DROP TABLE IF EXISTS node_traffic;
DROP TABLE IF EXISTS wlwtp_ports;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS promo_uses;
DROP TABLE IF EXISTS promo_codes;
DROP TABLE IF EXISTS subscriptions;
DROP TABLE IF EXISTS keys;
DROP TABLE IF EXISTS system_settings;
DROP TABLE IF EXISTS subscription_plans;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS email_tokens;
DROP TABLE IF EXISTS user_confirmations;
DROP TABLE IF EXISTS excluded_nodes;
DROP TABLE IF EXISTS torrent_blocked_entries;
DROP TABLE IF EXISTS blacklist_entries;
DROP TABLE IF EXISTS service_region_blocks;
DROP TABLE IF EXISTS anon_allowlist_entries;
DROP TABLE IF EXISTS whitelist_entries;
DROP TABLE IF EXISTS nodes;
DROP TABLE IF EXISTS users;
