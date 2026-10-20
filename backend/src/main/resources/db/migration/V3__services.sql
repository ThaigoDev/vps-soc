-- PM2-managed apps: latest snapshot on the host, history for charts and health.
ALTER TABLE hosts
    ADD COLUMN services JSONB,
    ADD COLUMN pm2      JSONB;

CREATE TABLE service_samples (
    id           BIGSERIAL PRIMARY KEY,
    host_id      VARCHAR(100) NOT NULL REFERENCES hosts (id),
    name         VARCHAR(255) NOT NULL,
    pm_id        INTEGER,
    recorded_at  TIMESTAMPTZ  NOT NULL,
    status       VARCHAR(30)  NOT NULL,
    cpu_percent  DOUBLE PRECISION,
    memory_bytes BIGINT,
    restarts     INTEGER
);
CREATE INDEX idx_service_samples ON service_samples (host_id, name, recorded_at DESC);

-- The service an incident is about (its own failure, or a port/process it owns).
ALTER TABLE incidents ADD COLUMN service VARCHAR(255);
CREATE INDEX idx_incidents_service ON incidents (host_id, service) WHERE service IS NOT NULL;
