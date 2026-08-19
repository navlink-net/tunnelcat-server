-- +goose Up
-- node_unreachable_events: per-observation record of one node being
-- unreachable from another node's point of view, resolved to a stable
-- node_id at write time (not just the address the observer currently
-- knows it by) -- so a node's unreachability history survives its own IP
-- rotation instead of fragmenting into separate per-address histories.
-- See db_unreachable.go.
CREATE TABLE node_unreachable_events (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts             BIGINT NOT NULL,
    reporter_type  TEXT   NOT NULL, -- 'client' (reporting a control) | 'control' (reporting an exit)
    target_type    TEXT   NOT NULL, -- 'control' | 'exit'
    target_node_id BIGINT,          -- resolved node id; NULL if the reported addr matched no known node
    target_addr    TEXT   NOT NULL  -- raw addr as reported, kept even when resolved (audit/debugging)
);
CREATE INDEX node_unreachable_events_target ON node_unreachable_events(target_type, target_node_id, ts);
CREATE INDEX node_unreachable_events_ts ON node_unreachable_events(ts);

-- +goose Down
DROP TABLE IF EXISTS node_unreachable_events;
