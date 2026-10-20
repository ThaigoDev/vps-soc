-- Installed packages per PM2 app (names and versions from the lockfile).
CREATE TABLE service_inventory (
    host_id     VARCHAR(100) NOT NULL REFERENCES hosts (id),
    service     VARCHAR(255) NOT NULL,
    pm2_home    VARCHAR(500),
    lockfile    VARCHAR(1000),
    hash        VARCHAR(64)  NOT NULL,
    packages    JSONB        NOT NULL,
    received_at TIMESTAMPTZ  NOT NULL,
    scanned_at  TIMESTAMPTZ,
    scan_error  TEXT,
    PRIMARY KEY (host_id, service)
);

-- Known vulnerabilities affecting those packages (from OSV.dev). Resolved when the
-- package is upgraded past the fix.
CREATE TABLE vulnerabilities (
    id            BIGSERIAL PRIMARY KEY,
    host_id       VARCHAR(100) NOT NULL REFERENCES hosts (id),
    service       VARCHAR(255) NOT NULL,
    package       VARCHAR(255) NOT NULL,
    version       VARCHAR(100) NOT NULL,
    dev           BOOLEAN      NOT NULL DEFAULT FALSE,
    vuln_id       VARCHAR(100) NOT NULL,
    aliases       JSONB,
    severity      VARCHAR(20)  NOT NULL,
    summary       TEXT,
    fixed_version VARCHAR(100),
    published     TIMESTAMPTZ,
    first_seen    TIMESTAMPTZ  NOT NULL,
    last_seen     TIMESTAMPTZ  NOT NULL,
    resolved_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_vulnerability ON vulnerabilities (host_id, service, package, version, vuln_id);
CREATE INDEX idx_vulnerabilities_open ON vulnerabilities (host_id, service) WHERE resolved_at IS NULL;

CREATE TABLE osv_cache (
    vuln_id    VARCHAR(100) PRIMARY KEY,
    data       JSONB       NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE service_samples
    ADD COLUMN probe_ok    BOOLEAN,
    ADD COLUMN http_status INTEGER,
    ADD COLUMN latency_ms  INTEGER,
    ADD COLUMN error_lines INTEGER;
