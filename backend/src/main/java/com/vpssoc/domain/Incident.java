package com.vpssoc.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "incidents")
public class Incident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hostId;
    private String ruleId;
    private String dedupKey;
    private String title;
    private String description;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    private int riskScore;

    @Enumerated(EnumType.STRING)
    private IncidentStatus status = IncidentStatus.OPEN;

    private String sourceIp;
    private String username;

    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> techniques = new ArrayList<>();

    private int eventCount;
    private Instant firstSeen;
    private Instant lastSeen;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant resolvedAt;
    private String resolutionNote;

    protected Incident() {
    }

    public Incident(String hostId, String ruleId, String dedupKey, Instant seenAt, Instant now) {
        this.hostId = hostId;
        this.ruleId = ruleId;
        this.dedupKey = dedupKey;
        this.firstSeen = seenAt;
        this.lastSeen = seenAt;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public void addTechniques(Collection<String> ids) {
        for (String id : ids) {
            if (!techniques.contains(id)) {
                techniques.add(id);
            }
        }
    }

    public void recordEvidence(Instant seenAt, int newEvents, Instant now) {
        eventCount += newEvents;
        if (seenAt.isAfter(lastSeen)) {
            lastSeen = seenAt;
        }
        updatedAt = now;
    }

    public void backdateFirstSeen(Instant t) {
        if (t.isBefore(firstSeen)) {
            firstSeen = t;
        }
    }

    public void changeStatus(IncidentStatus newStatus, String note, Instant now) {
        status = newStatus;
        updatedAt = now;
        if (note != null && !note.isBlank()) {
            resolutionNote = note;
        }
        resolvedAt = newStatus.isActive() ? null : now;
    }

    public Long getId() { return id; }
    public String getHostId() { return hostId; }
    public String getRuleId() { return ruleId; }
    public String getDedupKey() { return dedupKey; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = clamp(title); }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = Math.max(0, Math.min(100, riskScore)); }
    public IncidentStatus getStatus() { return status; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = clamp(username); }
    public List<String> getTechniques() { return techniques; }
    public int getEventCount() { return eventCount; }
    public Instant getFirstSeen() { return firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public Instant getResolvedAt() { return resolvedAt; }
    public String getResolutionNote() { return resolutionNote; }

    /** Titles can embed agent-reported paths; never let one overflow VARCHAR(255) and fail the batch. */
    private static String clamp(String s) {
        return s == null || s.length() <= 255 ? s : s.substring(0, 254) + "…";
    }
}
