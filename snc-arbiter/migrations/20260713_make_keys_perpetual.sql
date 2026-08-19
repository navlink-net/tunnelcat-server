-- Tunnel Cat is now free — make every existing paid key perpetual.
-- NOT run automatically. Apply manually against the production arbiter.db
-- once the free-key rollout is live:
--
--   sqlite3 /path/to/arbiter.db < 20260713_make_keys_perpetual.sql
--
-- Safe to re-run (idempotent): only touches rows that still have paid_until set.

UPDATE keys
SET paid_until = NULL,
    plan_pia = 0,
    reminder_sent = 0
WHERE paid_until IS NOT NULL;
