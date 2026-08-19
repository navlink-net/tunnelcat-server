-- +goose Up
-- node_active_users: the latest per-node snapshot of which accounts that
-- exit reported traffic for in its most recent /api/node/stats flush --
-- replaces (not accumulates into) the previous snapshot for that node on
-- every flush. See db_active_users.go.
--
-- This exists to fix a structural flicker in the "Active users" live
-- count: the old approach stamped a single last_seen per USER and compared
-- it against a fixed window equal to the exit-side flush interval (5 min),
-- so a genuinely-connected user could fall in or out of the count purely
-- because their specific exit's flush timer hadn't fired yet relative to
-- the moment the count was read -- no slack between the report cadence and
-- the count window. Freshness is now checked per NODE (is this node's
-- latest snapshot itself recent enough to trust) with a generous margin,
-- and the count is the union of currently-fresh nodes' latest username
-- lists -- see activeUserSet in db_active_users.go.
CREATE TABLE node_active_users (
    node_id     BIGINT PRIMARY KEY, -- no FK, matching node_unreachable_events' style: a
                                     -- decommissioned node's last snapshot is harmless
                                     -- leftover data, not worth cascading on delete
    usernames   TEXT   NOT NULL, -- JSON array of usernames, this node's latest flush
    reported_at BIGINT NOT NULL
);
CREATE INDEX node_active_users_reported_at ON node_active_users(reported_at);

-- +goose Down
DROP TABLE IF EXISTS node_active_users;
