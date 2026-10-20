package com.vpssoc.service;

import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.*;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.HostRepository;
import com.vpssoc.repository.IncidentRepository;
import com.vpssoc.repository.ServiceSampleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * What the dashboard shows for PM2 apps: the `pm2 list` row plus a health verdict with
 * its reasons, recent restarts, and the incidents that belong to the app.
 */
@Service
@Transactional(readOnly = true)
public class ServiceHealthService {

    public enum Health { HEALTHY, DEGRADED, DOWN, UNKNOWN }

    public record IncidentRef(long id, String ruleId, String title, Severity severity, IncidentStatus status, Instant lastSeen) {
        static IncidentRef of(Incident i) {
            return new IncidentRef(i.getId(), i.getRuleId(), i.getTitle(), i.getSeverity(), i.getStatus(), i.getLastSeen());
        }
    }

    public record ServiceView(String hostId, boolean hostOnline, Instant reportedAt, Map<String, Object> pm2,
                              Health health, List<String> reasons, long restartsLastHour, double memoryPercent,
                              List<IncidentRef> activeIncidents, long incidents30d) {
    }

    public record Sample(Instant t, String status, Double cpu, Double memoryMb, Integer restarts) {
    }

    public record ServiceDetail(ServiceView service, List<Sample> samples, List<com.vpssoc.api.ApiDtos.EventView> events,
                                List<IncidentRef> incidents) {
    }

    private final HostRepository hosts;
    private final IncidentRepository incidents;
    private final ServiceSampleRepository samples;
    private final EventRepository events;
    private final Clock clock;

    public ServiceHealthService(HostRepository hosts, IncidentRepository incidents, ServiceSampleRepository samples,
                                EventRepository events, Clock clock) {
        this.hosts = hosts;
        this.incidents = incidents;
        this.samples = samples;
        this.events = events;
        this.clock = clock;
    }

    public List<ServiceView> all() {
        Instant now = clock.instant();
        List<Incident> active = incidents.findByServiceIsNotNullAndStatusIn(IncidentStatus.ACTIVE);
        List<ServiceView> out = new ArrayList<>();
        for (Host h : hosts.findAllByOrderByIdAsc()) {
            if (h.getServices() == null) {
                continue;
            }
            Map<String, Long> minRestarts = new HashMap<>();
            for (Object[] r : samples.minRestartsSince(h.getId(), now.minus(Duration.ofHours(1)))) {
                if (r[1] instanceof Number n) {
                    minRestarts.put((String) r[0], n.longValue());
                }
            }
            for (Map<String, Object> s : h.getServices()) {
                out.add(view(h, s, active, minRestarts, now));
            }
        }
        return out;
    }

    public Optional<ServiceDetail> detail(String hostId, String name, int hours) {
        Instant now = clock.instant();
        return all().stream()
                .filter(v -> v.hostId().equals(hostId) && name.equals(v.pm2().get("name")))
                .findFirst()
                .map(v -> new ServiceDetail(v,
                        samples.findByHostIdAndNameAndRecordedAtAfterOrderByRecordedAtAsc(hostId, name, now.minus(Duration.ofHours(hours)))
                                .stream().map(x -> new Sample(x.getRecordedAt(), x.getStatus(), x.getCpuPercent(),
                                        x.getMemoryBytes() == null ? null : x.getMemoryBytes() / 1048576.0, x.getRestarts())).toList(),
                        events.serviceEvents(hostId, name, now.minus(Duration.ofDays(7))).stream()
                                .map(com.vpssoc.api.ApiDtos.EventView::of).toList(),
                        incidents.findByHostIdAndServiceOrderByLastSeenDesc(hostId, name).stream().limit(50).map(IncidentRef::of).toList()));
    }

    private ServiceView view(Host h, Map<String, Object> s, List<Incident> active, Map<String, Long> minRestarts, Instant now) {
        String name = String.valueOf(s.get("name"));
        String status = String.valueOf(s.get("status"));
        long restarts = s.get("restarts") instanceof Number n ? n.longValue() : 0;
        long lastHour = Math.max(0, restarts - minRestarts.getOrDefault(name, restarts));
        long mem = s.get("memoryBytes") instanceof Number n ? n.longValue() : 0;
        long hostMem = h.getMetrics() != null && h.getMetrics().get("memTotalBytes") instanceof Number n ? n.longValue() : 0;
        double memPct = hostMem > 0 ? 100.0 * mem / hostMem : 0;
        double cpu = s.get("cpuPercent") instanceof Number n ? n.doubleValue() : 0;

        List<IncidentRef> mine = active.stream()
                .filter(i -> i.getHostId().equals(h.getId()) && name.equals(i.getService()))
                .sorted(Comparator.comparing(Incident::getSeverity).reversed())
                .map(IncidentRef::of).toList();

        List<String> reasons = new ArrayList<>();
        Health health;
        boolean hostOnline = h.getStatus() == HostStatus.ONLINE;
        if (!hostOnline) {
            health = Health.UNKNOWN;
            reasons.add("O agente do host está offline: este é o último estado conhecido");
        } else if (status.equals("errored") || status.equals("stopped")) {
            health = Health.DOWN;
            reasons.add(status.equals("errored") ? "Status errored: caiu e o PM2 parou de reiniciar" : "Status stopped: está parado");
        } else {
            health = Health.HEALTHY;
            if (!status.equals("online")) {
                health = Health.DEGRADED;
                reasons.add("Status " + status);
            }
            if (lastHour >= 2) {
                health = Health.DEGRADED;
                reasons.add(lastHour + " reinícios na última hora");
            } else if (lastHour == 1) {
                reasons.add("1 reinício na última hora (deploy ou restart manual?)"); // one restart alone is not a problem
            }
            if (mine.stream().anyMatch(i -> i.ruleId().equals(RuleIds.SERVICE_CRASH_LOOP))) {
                health = Health.DEGRADED;
                reasons.add("Em crash loop");
            }
            if (mine.stream().anyMatch(i -> i.ruleId().equals(RuleIds.SERVICE_HIGH_MEMORY))) {
                health = Health.DEGRADED;
                reasons.add("Memória alta (%.0f%% da RAM)".formatted(memPct));
            }
            if (cpu >= 90) {
                health = Health.DEGRADED;
                reasons.add("CPU em %.0f%%".formatted(cpu));
            }
            if (mine.stream().anyMatch(i -> i.severity().atLeast(Severity.HIGH) && !i.ruleId().startsWith("SERVICE_"))) {
                health = Health.DEGRADED;
                reasons.add("Incidente de segurança ligado a este app");
            }
        }
        if (health == Health.HEALTHY && reasons.isEmpty()) {
            reasons.add("Online, sem reinícios recentes nem incidentes abertos");
        }
        long total30d = incidents.findByHostIdAndServiceOrderByLastSeenDesc(h.getId(), name).stream()
                .filter(i -> i.getLastSeen().isAfter(now.minus(Duration.ofDays(30)))).count();
        return new ServiceView(h.getId(), hostOnline, h.getLastSeen(), s, health, reasons, lastHour, memPct, mine, total30d);
    }
}
