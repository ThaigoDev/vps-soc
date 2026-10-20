package com.vpssoc.api;

import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.*;
import com.vpssoc.insight.Explanation;
import com.vpssoc.insight.IncidentExplainer;
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
                               String resolutionNote, Instant acknowledgedAt, Instant containedAt, String containmentNote) {
        public static IncidentView of(Incident i) {
            return new IncidentView(i.getId(), i.getHostId(), i.getRuleId(), i.getTitle(), i.getDescription(),
                    i.getSeverity(), i.getRiskScore(), i.getStatus(), i.getSourceIp(), i.getUsername(),
                    i.getTechniques().stream().map(Technique::of).toList(), i.getEventCount(), i.getFirstSeen(),
                    i.getLastSeen(), i.getCreatedAt(), i.getUpdatedAt(), i.getResolvedAt(), i.getResolutionNote(),
                    i.getAcknowledgedAt(), i.getContainedAt(), i.getContainmentNote());
        }
    }

    public record IncidentDetail(IncidentView incident, List<EventView> events, Explanation explanation,
                                 Explanation.IpProfile ip, List<ActionView> actions) {
    }

    public record ActionView(long id, String hostId, Long incidentId, ResponseAction.Type type, String label, String target,
                             Map<String, Object> params, ResponseAction.Status status, ResponseAction.Mode mode,
                             ResponseAction.Origin origin, String reason, String result, Map<String, Object> details,
                             Instant createdAt, Instant decidedAt, Instant completedAt) {
        public static ActionView of(ResponseAction a) {
            return new ActionView(a.getId(), a.getHostId(), a.getIncidentId(), a.getType(), IncidentExplainer.actionLabel(a),
                    a.getTarget(), a.getParams(), a.getStatus(), a.getMode(), a.getOrigin(), a.getReason(), a.getResult(),
                    a.getDetails(), a.getCreatedAt(), a.getDecidedAt(), a.getCompletedAt());
        }
    }

    public record BlockView(long id, String hostId, String ip, String reason, ResponseAction.Origin origin, Long incidentId,
                            Instant createdAt, Instant expiresAt) {
        public static BlockView of(IpBlock b) {
            return new BlockView(b.getId(), b.getHostId(), b.getIp(), b.getReason(), b.getOrigin(), b.getIncidentId(),
                    b.getCreatedAt(), b.getExpiresAt());
        }
    }

    public record BlockRequest(String hostId, String ip, Integer ttlHours, Long incidentId, String reason) {
    }

    public record StatusChange(IncidentStatus status, String note) {
    }

    public record HostView(String id, String hostname, String os, String agentVersion, String lastIp,
                           HostStatus status, Instant firstSeen, Instant lastSeen, int heartbeatIntervalSeconds,
                           Map<String, Object> metrics, List<Map<String, Object>> openPorts,
                           Map<String, Object> posture, Map<String, Object> response) {
        public static HostView of(Host h) {
            return new HostView(h.getId(), h.getHostname(), h.getOs(), h.getAgentVersion(), h.getLastIp(),
                    h.getStatus(), h.getFirstSeen(), h.getLastSeen(), h.getHeartbeatIntervalSeconds(),
                    h.getMetrics(), h.getOpenPorts(), h.getPosture(), h.getResponse());
        }
    }

    public record MetricPoint(Instant t, Double cpu, Double mem, Double disk, Double load1, Double swap,
                              Double netRx, Double netTx, Integer tcp, Integer processes) {
        public static MetricPoint of(HostMetric m) {
            return new MetricPoint(m.getRecordedAt(), m.getCpuPercent(), m.getMemPercent(), m.getDiskPercent(), m.getLoad1(),
                    m.getSwapPercent(), m.getNetRxBps(), m.getNetTxBps(), m.getTcpEstablished(), m.getProcesses());
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

    /** SOC performance and exposure over a window (seconds for the mean times; null = no data). */
    public record Kpis(int windowDays, Double mttdSeconds, Double mttaSeconds, Double mttrSeconds, Double mttcSeconds,
                       long incidentsOpened, long incidentsResolved, long falsePositives, double falsePositiveRate,
                       long contained, long containedAutomatically, double autoContainmentRate, long backlog,
                       long actionsAuto, long actionsManual, long actionsFailed, long actionsAwaitingApproval,
                       long activeBlocks, long droppedPackets, double eventsPerMinute, long maxDataLagSeconds,
                       List<RuleCount> topRules, List<NameCount> topUsernames, List<DayCount> daily) {
    }

    public record RuleCount(String ruleId, long incidents, long falsePositives) {
    }

    public record NameCount(String name, long count) {
    }

    public record DayCount(String day, long opened, long closed) {
    }
}
