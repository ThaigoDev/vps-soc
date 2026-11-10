package com.vpssoc.vuln;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** The packages one PM2 app has installed, as last reported by the agent. */
@Entity
@Table(name = "service_inventory")
public class ServiceInventory {

    @Embeddable
    public record Key(String hostId, String service) implements Serializable {
    }

    @EmbeddedId
    private Key key;

    @Column(name = "pm2_home")
    private String pm2Home;
    private String lockfile;
    private String hash;

    @JdbcTypeCode(SqlTypes.JSON)
    private List<Map<String, Object>> packages;

    private Instant receivedAt;
    private Instant scannedAt;
    private String scanError;

    protected ServiceInventory() {
    }

    public ServiceInventory(Key key) {
        this.key = key;
    }

    public void update(String pm2Home, String lockfile, String hash, List<Map<String, Object>> packages, Instant now) {
        this.pm2Home = pm2Home;
        this.lockfile = lockfile;
        this.hash = hash;
        this.packages = packages;
        this.receivedAt = now;
    }

    public void scanned(Instant at, String error) {
        this.scannedAt = at;
        this.scanError = error;
    }

    public Key getKey() { return key; }
    public String getPm2Home() { return pm2Home; }
    public String getLockfile() { return lockfile; }
    public String getHash() { return hash; }
    public List<Map<String, Object>> getPackages() { return packages; }
    public Instant getReceivedAt() { return receivedAt; }
    public Instant getScannedAt() { return scannedAt; }
    public String getScanError() { return scanError; }
}
