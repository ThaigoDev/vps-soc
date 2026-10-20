package com.vpssoc.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/** A containment action for the agent to run (or one the agent already ran on its own). */
@Entity
@Table(name = "response_actions")
public class ResponseAction {

    public enum Type { BLOCK_IP, UNBLOCK_IP, KILL_PROCESS, DISK_CLEANUP, RESTART_SERVICE, PM2_RESTART }

    public enum Status {
        /** Waiting for a human to approve. */
        PROPOSED,
        /** Approved (or automatic), waiting for the agent to pick it up. */
        PENDING,
        SENT, SUCCEEDED, FAILED,
        /** The agent refused it (its own safety checks). */
        REJECTED,
        DISMISSED, EXPIRED;

        public boolean open() {
            return this == PROPOSED || this == PENDING || this == SENT;
        }
    }

    public enum Mode { AUTO, MANUAL }

    public enum Origin { SOC, AGENT }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hostId;
    private Long incidentId;

    @Enumerated(EnumType.STRING)
    private Type type;

    private String target;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> params = new HashMap<>();

    @Enumerated(EnumType.STRING)
    private Status status;

    @Enumerated(EnumType.STRING)
    private Mode mode;

    @Enumerated(EnumType.STRING)
    private Origin origin;

    private String reason;
    private String result;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> details;

    private Instant createdAt;
    private Instant decidedAt;
    private Instant dispatchedAt;
    private Instant completedAt;

    protected ResponseAction() {
    }

    public ResponseAction(String hostId, Long incidentId, Type type, String target, Map<String, Object> params,
                          Status status, Mode mode, Origin origin, String reason, Instant now) {
        this.hostId = hostId;
        this.incidentId = incidentId;
        this.type = type;
        this.target = target.length() > 255 ? target.substring(0, 255) : target;
        this.params = params;
        this.status = status;
        this.mode = mode;
        this.origin = origin;
        this.reason = reason;
        this.createdAt = now;
        if (status == Status.PENDING) {
            this.decidedAt = now;
        }
    }

    public void approve(Instant now) {
        status = Status.PENDING;
        mode = Mode.MANUAL;
        decidedAt = now;
    }

    /** A more serious incident wants this queued action now: run it without waiting for approval. */
    public void escalate(String why, Instant now) {
        status = Status.PENDING;
        mode = Mode.AUTO;
        decidedAt = now;
        reason = why;
    }

    public void setParams(Map<String, Object> params) {
        this.params = params;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public void dismiss(Instant now) {
        status = Status.DISMISSED;
        decidedAt = now;
        completedAt = now;
    }

    public void dispatch(Instant now) {
        status = Status.SENT;
        dispatchedAt = now;
    }

    public void complete(Status s, String result, Map<String, Object> details, Instant now) {
        this.status = s;
        this.result = result == null ? null : result.length() > 4000 ? result.substring(0, 4000) : result;
        this.details = details;
        this.completedAt = now;
    }

    public Long getId() { return id; }
    public String getHostId() { return hostId; }
    public Long getIncidentId() { return incidentId; }
    public void setIncidentId(Long incidentId) { this.incidentId = incidentId; }
    public Type getType() { return type; }
    public String getTarget() { return target; }
    public Map<String, Object> getParams() { return params; }
    public Status getStatus() { return status; }
    public Mode getMode() { return mode; }
    public Origin getOrigin() { return origin; }
    public String getReason() { return reason; }
    public String getResult() { return result; }
    public Map<String, Object> getDetails() { return details; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getDecidedAt() { return decidedAt; }
    public Instant getDispatchedAt() { return dispatchedAt; }
    public Instant getCompletedAt() { return completedAt; }
}
