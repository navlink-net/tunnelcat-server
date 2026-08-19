-- +goose Up
CREATE TABLE exit_rejected_sessions (
    id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts      BIGINT NOT NULL,
    node_id BIGINT NOT NULL,
    count   BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX exit_rejected_sessions_ts ON exit_rejected_sessions(ts);

-- +goose Down
DROP TABLE exit_rejected_sessions;
