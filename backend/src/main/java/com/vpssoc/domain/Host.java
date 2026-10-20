package com.vpssoc.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "hosts")
public class Host {

    @Id
    private String id;
    private String hostname;
    private String os;
    private String agentVersion;
    private String lastIp;

    @Enumerated(EnumType.STRING)
    private HostStatus status = HostStatus.ONLINE;

    @Column(name = "heartbeat_interval")
    private int heartbeatIntervalSeconds = 30;

    private Instant firstSeen;
    private Instant lastSeen;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> metrics;

    @JdbcTypeCode(SqlTypes.JSON)
    private List<Map<String, Object>> openPorts;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> posture;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> response;

    protected Host() {
    }

    public Host(String id, Instant now) {
        this.id = id;
        this.firstSeen = now;
        this.lastSeen = now;
    }

    public String getId() { return id; }
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }
    public String getAgentVersion() { return agentVersion; }
    public void setAgentVersion(String agentVersion) { this.agentVersion = agentVersion; }
    public String getLastIp() { return lastIp; }
    public void setLastIp(String lastIp) { this.lastIp = lastIp; }
    public HostStatus getStatus() { return status; }
    public void setStatus(HostStatus status) { this.status = status; }
    public int getHeartbeatIntervalSeconds() { return heartbeatIntervalSeconds; }
    public void setHeartbeatIntervalSeconds(int s) { this.heartbeatIntervalSeconds = s; }
    public Instant getFirstSeen() { return firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }
    public Map<String, Object> getMetrics() { return metrics; }
    public void setMetrics(Map<String, Object> metrics) { this.metrics = metrics; }
    public List<Map<String, Object>> getOpenPorts() { return openPorts; }
    public void setOpenPorts(List<Map<String, Object>> openPorts) { this.openPorts = openPorts; }
    public Map<String, Object> getPosture() { return posture; }
    public void setPosture(Map<String, Object> posture) { this.posture = posture; }
    public Map<String, Object> getResponse() { return response; }
    public void setResponse(Map<String, Object> response) { this.response = response; }
}
