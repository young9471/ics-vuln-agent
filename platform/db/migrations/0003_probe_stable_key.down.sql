DROP INDEX IF EXISTS uq_protocol_probes_key;
ALTER TABLE protocol_probes DROP COLUMN IF EXISTS probe_key;