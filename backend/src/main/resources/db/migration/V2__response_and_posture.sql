-- SOC timing KPIs (MTTA, MTTC) and containment state.
ALTER TABLE incidents
    ADD COLUMN acknowledged_at  TIMESTAMPTZ,
    ADD COLUMN contained_at     TIMESTAMPTZ,
    ADD COLUMN containment_note TEXT;

-- Containment actions: proposed by playbooks, approved (or automatic), executed by the agent.
CREATE TABLE response_actions (
    id            BIGSERIAL PRIMARY KEY,
    host_id       VARCHAR(100) NOT NULL REFERENCES hosts (id),
    incident_id   BIGINT REFERENCES incidents (id) ON DELETE SET NULL,
    type          VARCHAR(30)  NOT NULL,
    target        VARCHAR(255) NOT NULL,
    params        JSONB        NOT NULL DEFAULT '{}',
    status        VARCHAR(20)  NOT NULL,
    mode          VARCHAR(10)  NOT NULL,
    origin        VARCHAR(10)  NOT NULL,
    reason        TEXT,
    result        TEXT,
    details       JSONB,
    created_at    TIMESTAMPTZ  NOT NULL,
    decided_at    TIMESTAMPTZ,
    dispatched_at TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ
);
CREATE INDEX idx_actions_host_status ON response_actions (host_id, status);
CREATE INDEX idx_actions_incident ON response_actions (incident_id);
CREATE INDEX idx_actions_created ON response_actions (created_at DESC);

CREATE TABLE ip_blocks (
    id          BIGSERIAL PRIMARY KEY,
    host_id     VARCHAR(100) NOT NULL REFERENCES hosts (id),
    ip          VARCHAR(45)  NOT NULL,
    reason      TEXT,
    origin      VARCHAR(10)  NOT NULL,
    action_id   BIGINT REFERENCES response_actions (id) ON DELETE SET NULL,
    incident_id BIGINT REFERENCES incidents (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ  NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    removed_at  TIMESTAMPTZ
);
CREATE INDEX idx_ip_blocks_active ON ip_blocks (host_id, ip) WHERE removed_at IS NULL;

-- Extra host telemetry.
ALTER TABLE host_metrics
    ADD COLUMN swap_percent    DOUBLE PRECISION,
    ADD COLUMN net_rx_bps      DOUBLE PRECISION,
    ADD COLUMN net_tx_bps      DOUBLE PRECISION,
    ADD COLUMN tcp_established INTEGER,
    ADD COLUMN processes       INTEGER;

ALTER TABLE hosts
    ADD COLUMN posture  JSONB,
    ADD COLUMN response JSONB;
