package com.vpssoc.ingest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public final class IngestDtos {

    public static final String HOST_ID_PATTERN = "[A-Za-z0-9._-]{1,100}";

    private IngestDtos() {
    }

    public record EventBatch(
            @NotBlank @Pattern(regexp = HOST_ID_PATTERN) String hostId,
            @NotNull @Size(max = 1000) List<@Valid AgentEvent> events) {
    }

    public record AgentEvent(
            @NotBlank String type,
            Instant occurredAt,
            String sourceIp,
            String username,
            String message,
            Map<String, Object> metadata) {
    }

    public record Heartbeat(
            @NotBlank @Pattern(regexp = HOST_ID_PATTERN) String hostId,
            String hostname,
            String os,
            String agentVersion,
            Integer heartbeatIntervalSeconds,
            Metrics metrics,
            @Size(max = 2000) List<Map<String, Object>> openPorts,
            Map<String, Object> posture,
            Map<String, Object> response) {
    }

    public record Metrics(
            Double cpuPercent,
            Double memPercent,
            Long memTotalBytes,
            Long memUsedBytes,
            Double diskPercent,
            Long diskTotalBytes,
            Long diskUsedBytes,
            Double load1,
            Double load5,
            Double load15,
            Long uptimeSeconds,
            Double swapPercent,
            Double netRxBps,
            Double netTxBps,
            Integer tcpEstablished,
            Integer processes) {
    }

    public record IngestResult(int accepted, int skipped) {
    }

    public record ActionPoll(@NotBlank @Pattern(regexp = HOST_ID_PATTERN) String hostId) {
    }

    public record ActionOrder(long id, String type, Map<String, Object> params) {
    }

    public record ActionOrders(List<ActionOrder> actions) {
    }

    public record ActionResult(@NotBlank @Pattern(regexp = HOST_ID_PATTERN) String hostId, @NotBlank String status,
                               String output, Map<String, Object> details) {
    }
}
