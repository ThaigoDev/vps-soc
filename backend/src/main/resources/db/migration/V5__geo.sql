-- Where each server is: the public IP the agent reports, or one set by hand in the dashboard.
ALTER TABLE hosts ADD COLUMN public_ip VARCHAR(45);
ALTER TABLE hosts ADD COLUMN manual_ip VARCHAR(45);

-- IP geolocation cache (servers and attackers), so each address is looked up once.
CREATE TABLE ip_geo (
    ip           VARCHAR(45) PRIMARY KEY,
    ok           BOOLEAN      NOT NULL,
    country      VARCHAR(100),
    country_code VARCHAR(2),
    region       VARCHAR(100),
    city         VARCHAR(100),
    lat          DOUBLE PRECISION,
    lon          DOUBLE PRECISION,
    org          VARCHAR(255),
    fetched_at   TIMESTAMPTZ  NOT NULL
);
