-- Stable probe identity: [probe:<id>] evidence references in delivered
-- documents must survive findings re-syncs, so probes are upserted by
-- (case_id, probe_key) instead of full DELETE+INSERT.
ALTER TABLE protocol_probes ADD COLUMN IF NOT EXISTS probe_key TEXT NOT NULL DEFAULT '';

-- Partial index: legacy rows keep probe_key='' until their next sync; they must
-- not collide with each other while the migration runs.
CREATE UNIQUE INDEX IF NOT EXISTS uq_protocol_probes_key
    ON protocol_probes(case_id, probe_key) WHERE probe_key <> '';