-- +goose Up
-- node_addr_rotations: every time a control/exit node's address changes
-- (IP-rotation daemons on navlink.net, or any other admin address update),
-- recorded with both the old and new address. See db_node_rotations.go.
CREATE TABLE node_addr_rotations (
    id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts        BIGINT NOT NULL,
    node_id   BIGINT NOT NULL,
    node_type TEXT   NOT NULL, -- 'control' | 'exit'
    old_addr  TEXT   NOT NULL,
    new_addr  TEXT   NOT NULL
);
CREATE INDEX node_addr_rotations_type_ts ON node_addr_rotations(node_type, ts);

-- +goose Down
DROP TABLE IF EXISTS node_addr_rotations;
