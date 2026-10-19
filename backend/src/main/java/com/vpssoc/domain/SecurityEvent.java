package com.vpssoc.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;

@Entity
@Table(name = "events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hostId;

    @Enumerated(EnumType.STRING)
    private EventType type;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    private Instant occurredAt;
    private Instant receivedAt;
    private String sourceIp;
    private String username;
    private String message;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> metadata;

    protected SecurityEvent() {
    }

    public SecurityEvent(String hostId, EventType type, Instant occurredAt, Instant receivedAt,
                         String sourceIp, String username, String message, Map<String, Object> metadata) {
        this.hostId = hostId;
        this.type = type;
        this.severity = type.defaultSeverity();
        this.occurredAt = occurredAt;
        this.receivedAt = receivedAt;
        this.sourceIp = sourceIp;
        this.username = username;
        this.message = message;
        this.metadata = metadata;
    }

    public Long getId() { return id; }
    public String getHostId() { return hostId; }
    public EventType getType() { return type; }
    public Severity getSeverity() { return severity; }
    public Instant getOccurredAt() { return occurredAt; }
    public Instant getReceivedAt() { return receivedAt; }
    public String getSourceIp() { return sourceIp; }
    public String getUsername() { return username; }
    public String getMessage() { return message; }
    public Map<String, Object> getMetadata() { return metadata; }

    public Object meta(String key) {
        return metadata == null ? null : metadata.get(key);
    }
}
