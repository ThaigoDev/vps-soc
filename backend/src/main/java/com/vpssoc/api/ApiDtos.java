package com.vpssoc.api;

import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.*;
import org.springframework.data.domain.Page;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** Response shapes for the dashboard API. */
public final class ApiDtos {

    private ApiDtos() {
    }

    public record PageResponse<T>(List<T> content, long totalElements, int page, int size, int totalPages) {
        public static <E, T> PageResponse<T> of(Page<E> page, Function<E, T> mapper) {
            return new PageResponse<>(page.getContent().stream().map(mapper).toList(),
                    page.getTotalElements(), page.getNumber(), page.getSize(), page.getTotalPages());
        }
    }

    public record EventView(long id, String hostId, EventType type, EventType.Category category, Severity severity,
                            Instant occurredAt, String sourceIp, String username, String message,
                            Map<String, Object> metadata) {
        public static EventView of(SecurityEvent e) {
            return new EventView(e.getId(), e.getHostId(), e.getType(), e.getType().category(), e.getSeverity(),
                    e.getOccurredAt(), e.getSourceIp(), e.getUsername(), e.getMessage(), e.getMetadata());
        }
    }

    public record Technique(String id, String name, String url) {
        public static Technique of(String id) {
            return new Technique(id, Mitre.name(id), Mitre.url(id));
        }
    }

    public record IncidentView(long id, String hostId, String ruleId, String title, String description,
                               Severity severity, int riskScore, IncidentStatus status, String sourceIp,
                               String username, List<Technique> techniques, int eventCount, Instant firstSeen,
                               Instant lastSeen, Instant createdAt, Instant updatedAt, Instant resolvedAt,
                               String resolutionNote) {
        public static IncidentView of(Incident i) {
            return new IncidentView(i.getId(), i.getHostId(), i.getRuleId(), i.getTitle(), i.getDescription(),
                    i.getSeverity(), i.getRiskScore(), i.getStatus(), i.getSourceIp(), i.getUsername(),
                    i.getTechniques().stream().map(Technique::of).toList(), i.getEventCount(), i.getFirstSeen(),
                    i.getLastSeen(), i.getCreatedAt(), i.getUpdatedAt(), i.getResolvedAt(), i.getResolutionNote());
        }
    }

    public record IncidentDetail(IncidentView incident, List<EventView> events) {
    }

    public record StatusChange(IncidentStatus status, String note) {
    }

    public record HostView(String id, String hostname, String os, String agentVersion, String lastIp,
                           HostStatus status, Instant firstSeen, Instant lastSeen, int heartbeatIntervalSeconds,
                           Map<String, Object> metrics, List<Map<String, Object>> openPorts) {
        public static HostView of(Host h) {
            return new HostView(h.getId(), h.getHostname(), h.getOs(), h.getAgentVersion(), h.getLastIp(),
                    h.getStatus(), h.getFirstSeen(), h.getLastSeen(), h.getHeartbeatIntervalSeconds(),
                    h.getMetrics(), h.getOpenPorts());
        }
    }

    public record MetricPoint(Instant t, Double cpu, Double mem, Double disk, Double load1) {
        public static MetricPoint of(HostMetric m) {
            return new MetricPoint(m.getRecordedAt(), m.getCpuPercent(), m.getMemPercent(), m.getDiskPercent(), m.getLoad1());
        }
    }

    public record Summary(int securityScore, String posture, Map<Severity, Long> openIncidents, long totalOpenIncidents,
                          long events24h, long authFailures24h, long attackerIps24h, long hostsOnline, long hostsTotal) {
    }

    public record TimelineBucket(Instant hour, long authFailures, long authSuccesses, long privilege, long network,
                                 long other, long integrity) {
    }

    public record SourceIpStats(String ip, long failures, long successes, long usernames, Instant lastSeen) {
    }
}
