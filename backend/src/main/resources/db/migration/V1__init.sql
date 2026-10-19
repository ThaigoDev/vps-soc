CREATE TABLE hosts (
    id                  VARCHAR(100) PRIMARY KEY,
    hostname            VARCHAR(255),
    os                  VARCHAR(255),
    agent_version       VARCHAR(50),
    last_ip             VARCHAR(45),
    status              VARCHAR(20)  NOT NULL DEFAULT 'ONLINE',
    heartbeat_interval  INTEGER      NOT NULL DEFAULT 30,
    first_seen          TIMESTAMPTZ  NOT NULL,
    last_seen           TIMESTAMPTZ  NOT NULL,
    metrics             JSONB,
    open_ports          JSONB
);

CREATE TABLE events (
    id           BIGSERIAL PRIMARY KEY,
    host_id      VARCHAR(100) NOT NULL REFERENCES hosts (id),
    type         VARCHAR(50)  NOT NULL,
    severity     VARCHAR(20)  NOT NULL,
    occurred_at  TIMESTAMPTZ  NOT NULL,
    received_at  TIMESTAMPTZ  NOT NULL,
    source_ip    VARCHAR(45),
    username     VARCHAR(255),
    message      TEXT,
    metadata     JSONB
);
CREATE INDEX idx_events_occurred ON events (occurred_at DESC);
CREATE INDEX idx_events_host_type_time ON events (host_id, type, occurred_at DESC);
CREATE INDEX idx_events_ip_time ON events (source_ip, occurred_at DESC) WHERE source_ip IS NOT NULL;

CREATE TABLE host_metrics (
    id           BIGSERIAL PRIMARY KEY,
    host_id      VARCHAR(100) NOT NULL REFERENCES hosts (id),
    recorded_at  TIMESTAMPTZ  NOT NULL,
    cpu_percent  DOUBLE PRECISION,
    mem_percent  DOUBLE PRECISION,
    disk_percent DOUBLE PRECISION,
    load1        DOUBLE PRECISION
);
CREATE INDEX idx_host_metrics_host_time ON host_metrics (host_id, recorded_at DESC);

CREATE TABLE incidents (
    id           BIGSERIAL PRIMARY KEY,
    host_id      VARCHAR(100) NOT NULL REFERENCES hosts (id),
    rule_id      VARCHAR(60)  NOT NULL,
    dedup_key    VARCHAR(255) NOT NULL,
    title        VARCHAR(255) NOT NULL,
    description  TEXT,
    severity     VARCHAR(20)  NOT NULL,
    risk_score   INTEGER      NOT NULL,
    status       VARCHAR(20)  NOT NULL,
    source_ip    VARCHAR(45),
    username     VARCHAR(255),
    techniques   JSONB        NOT NULL DEFAULT '[]',
    event_count  INTEGER      NOT NULL DEFAULT 0,
    first_seen   TIMESTAMPTZ  NOT NULL,
    last_seen    TIMESTAMPTZ  NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL,
    updated_at   TIMESTAMPTZ  NOT NULL,
    resolved_at  TIMESTAMPTZ,
    resolution_note TEXT
);
CREATE INDEX idx_incidents_status ON incidents (status, last_seen DESC);
-- At most one active incident per rule + key: new evidence is attached to it.
CREATE UNIQUE INDEX uq_incidents_active ON incidents (host_id, rule_id, dedup_key)
    WHERE status IN ('OPEN', 'ACKNOWLEDGED');

CREATE TABLE incident_events (
    incident_id BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    event_id    BIGINT NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, event_id)
);
CREATE INDEX idx_incident_events_event ON incident_events (event_id);
