package com.vpssoc.domain;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "host_metrics")
public class HostMetric {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hostId;
    private Instant recordedAt;
    private Double cpuPercent;
    private Double memPercent;
    private Double diskPercent;
    private Double load1;
    private Double swapPercent;
    private Double netRxBps;
    private Double netTxBps;
    private Integer tcpEstablished;
    private Integer processes;

    protected HostMetric() {
    }

    public HostMetric(String hostId, Instant recordedAt, Double cpuPercent, Double memPercent,
                      Double diskPercent, Double load1) {
        this.hostId = hostId;
        this.recordedAt = recordedAt;
        this.cpuPercent = cpuPercent;
        this.memPercent = memPercent;
        this.diskPercent = diskPercent;
        this.load1 = load1;
    }

    public HostMetric withExtras(Double swapPercent, Double netRxBps, Double netTxBps, Integer tcpEstablished, Integer processes) {
        this.swapPercent = swapPercent;
        this.netRxBps = netRxBps;
        this.netTxBps = netTxBps;
        this.tcpEstablished = tcpEstablished;
        this.processes = processes;
        return this;
    }

    public Instant getRecordedAt() { return recordedAt; }
    public Double getCpuPercent() { return cpuPercent; }
    public Double getMemPercent() { return memPercent; }
    public Double getDiskPercent() { return diskPercent; }
    public Double getLoad1() { return load1; }
    public Double getSwapPercent() { return swapPercent; }
    public Double getNetRxBps() { return netRxBps; }
    public Double getNetTxBps() { return netTxBps; }
    public Integer getTcpEstablished() { return tcpEstablished; }
    public Integer getProcesses() { return processes; }
}
