-- +goose Up
-- Log-upload privacy toggles, 2026-09-18: log_upload_enabled is the user's
-- own self-service preference (default on, matching prior always-on
-- behavior); log_upload_admin_disabled is a staff override that forces
-- uploads off regardless of the user's own setting -- see
-- (*DB).logUploadAllowed in db.go. Neither affects local on-device logging
-- or a manual Share-Logs export, only the automatic background upload of a
-- client's device-log ring buffer (apiLogClientUpload).
ALTER TABLE users ADD COLUMN log_upload_enabled BIGINT NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN log_upload_admin_disabled BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE users DROP COLUMN log_upload_enabled;
ALTER TABLE users DROP COLUMN log_upload_admin_disabled;
