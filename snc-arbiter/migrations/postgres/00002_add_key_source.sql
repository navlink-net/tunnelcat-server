-- +goose Up
ALTER TABLE keys ADD COLUMN source TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE keys DROP COLUMN source;
