package com.vpssoc.domain;

import jakarta.persistence.*;

import java.time.Instant;

/** One heartbeat's view of a PM2 app: status, CPU, memory and restart counter. */
@Entity
@Table(name = "service_samples")
public class ServiceSample {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hostId;
    private String name;
    private Integer pmId;
    private Instant recordedAt;
    private String status;
    private Double cpuPercent;
    private Long memoryBytes;
    private Integer restarts;
    private Boolean probeOk;
    private Integer httpStatus;
    private Integer latencyMs;
    private Integer errorLines;

    protected ServiceSample() {
    }

    public ServiceSample(String hostId, String name, Integer pmId, Instant recordedAt, String status,
                         Double cpuPercent, Long memoryBytes, Integer restarts) {
        this.hostId = hostId;
        this.name = name;
        this.pmId = pmId;
        this.recordedAt = recordedAt;
        this.status = status;
        this.cpuPercent = cpuPercent;
        this.memoryBytes = memoryBytes;
        this.restarts = restarts;
    }

    public ServiceSample withHealth(Boolean probeOk, Integer httpStatus, Integer latencyMs, Integer errorLines) {
        this.probeOk = probeOk;
        this.httpStatus = httpStatus;
        this.latencyMs = latencyMs;
        this.errorLines = errorLines;
        return this;
    }

    public String getHostId() { return hostId; }
    public String getName() { return name; }
    public Integer getPmId() { return pmId; }
    public Instant getRecordedAt() { return recordedAt; }
    public String getStatus() { return status; }
    public Double getCpuPercent() { return cpuPercent; }
    public Long getMemoryBytes() { return memoryBytes; }
    public Integer getRestarts() { return restarts; }
    public Boolean getProbeOk() { return probeOk; }
    public Integer getHttpStatus() { return httpStatus; }
    public Integer getLatencyMs() { return latencyMs; }
    public Integer getErrorLines() { return errorLines; }
}
