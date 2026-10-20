package com.vpssoc.domain;

import jakarta.persistence.*;

import java.time.Instant;

/** An address blocked on a host's firewall. Active while not removed and not expired. */
@Entity
@Table(name = "ip_blocks")
public class IpBlock {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hostId;
    private String ip;
    private String reason;

    @Enumerated(EnumType.STRING)
    private ResponseAction.Origin origin;

    private Long actionId;
    private Long incidentId;
    private Instant createdAt;
    private Instant expiresAt;
    private Instant removedAt;

    protected IpBlock() {
    }

    public IpBlock(String hostId, String ip, String reason, ResponseAction.Origin origin, Long actionId, Long incidentId,
                   Instant createdAt, Instant expiresAt) {
        this.hostId = hostId;
        this.ip = ip;
        this.reason = reason;
        this.origin = origin;
        this.actionId = actionId;
        this.incidentId = incidentId;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public boolean activeAt(Instant now) {
        return removedAt == null && expiresAt.isAfter(now);
    }

    public void remove(Instant now) {
        removedAt = now;
    }

    public void extendTo(Instant until) {
        if (until.isAfter(expiresAt)) {
            expiresAt = until;
        }
    }

    public Long getId() { return id; }
    public String getHostId() { return hostId; }
    public String getIp() { return ip; }
    public String getReason() { return reason; }
    public ResponseAction.Origin getOrigin() { return origin; }
    public Long getActionId() { return actionId; }
    public Long getIncidentId() { return incidentId; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRemovedAt() { return removedAt; }
}
