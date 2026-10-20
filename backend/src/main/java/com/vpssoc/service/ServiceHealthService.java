package com.vpssoc.service;

import com.vpssoc.api.ApiDtos;
import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.*;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.HostRepository;
import com.vpssoc.repository.IncidentRepository;
import com.vpssoc.repository.ServiceSampleRepository;
import com.vpssoc.vuln.ServiceInventory;
import com.vpssoc.vuln.Vulnerability;
import com.vpssoc.vuln.VulnerabilityService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * What the dashboard shows for PM2 apps: the `pm2 list` row plus a health verdict with its
 * reasons, a security score with its checklist, dependency vulnerabilities, availability
 * over 24 h, and the incidents that belong to the app.
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

    public record Availability(Double uptimePct, Double probeOkPct, Double latencyP50Ms, Double latencyP95Ms, long errorsLastHour) {
    }

    public record ServiceView(String hostId, boolean hostOnline, Instant reportedAt, Map<String, Object> pm2,
                              Health health, List<String> reasons, long restartsLastHour, double memoryPercent,
                              List<IncidentRef> activeIncidents, long incidents30d,
                              int securityScore, List<ServiceSecurity.Check> checks,
                              Map<Vulnerability.Level, Long> vulnerabilities, Availability availability) {
    }

    public record Sample(Instant t, String status, Double cpu, Double memoryMb, Integer restarts, Integer latencyMs,
                         Boolean probeOk, Integer errorLines) {
    }

    public record VulnView(long id, String pkg, String version, boolean dev, String vulnId, String cve, List<String> aliases,
                           Vulnerability.Level severity, String summary, String fixedVersion, Instant published,
                           Instant firstSeen, String url) {
        static VulnView of(Vulnerability v) {
            String cve = v.getAliases() == null ? null : v.getAliases().stream().filter(a -> a.startsWith("CVE-")).findFirst().orElse(null);
            return new VulnView(v.getId(), v.getPkg(), v.getVersion(), v.isDev(), v.getVulnId(), cve, v.getAliases(), v.getSeverity(),
                    v.getSummary(), v.getFixedVersion(), v.getPublished(), v.getFirstSeen(), "https://osv.dev/vulnerability/" + v.getVulnId());
        }
    }

    public record InventoryView(int packages, int devPackages, String lockfile, Instant receivedAt, Instant scannedAt, String scanError) {
    }

    public record ServiceDetail(ServiceView service, List<Sample> samples, List<ApiDtos.EventView> events,
                                List<IncidentRef> incidents, List<VulnView> vulnerabilities, InventoryView inventory) {
    }

    private final HostRepository hosts;
    private final IncidentRepository incidents;
    private final ServiceSampleRepository samples;
    private final EventRepository events;
    private final VulnerabilityService vulns;
    private final Clock clock;

    public ServiceHealthService(HostRepository hosts, IncidentRepository incidents, ServiceSampleRepository samples,
                                EventRepository events, VulnerabilityService vulns, Clock clock) {
        this.hosts = hosts;
        this.incidents = incidents;
        this.samples = samples;
        this.events = events;
        this.vulns = vulns;
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
            Map<String, Availability> avail = new HashMap<>();
            for (Object[] r : samples.availability(h.getId(), now.minus(Duration.ofHours(24)), now.minus(Duration.ofHours(1)))) {
                long total = num(r[1]), online = num(r[2]), probes = num(r[3]), probesOk = num(r[4]);
                avail.put((String) r[0], new Availability(total == 0 ? null : 100.0 * online / total,
                        probes == 0 ? null : 100.0 * probesOk / probes, dbl(r[5]), dbl(r[6]), num(r[7])));
            }
            for (Map<String, Object> s : h.getServices()) {
                out.add(view(h, s, active, minRestarts, avail, now));
            }
        }
        return out;
    }

    public Optional<ServiceDetail> detail(String hostId, String name, int hours) {
        Instant now = clock.instant();
        return all().stream()
                .filter(v -> v.hostId().equals(hostId) && name.equals(v.pm2().get("name")))
                .findFirst()
                .map(v -> {
                    ServiceInventory inv = vulns.inventory(hostId, name).orElse(null);
                    InventoryView iv = inv == null ? null : new InventoryView(
                            inv.getPackages() == null ? 0 : inv.getPackages().size(),
                            inv.getPackages() == null ? 0 : (int) inv.getPackages().stream().filter(p -> Boolean.TRUE.equals(p.get("dev"))).count(),
                            inv.getLockfile(), inv.getReceivedAt(), inv.getScannedAt(), inv.getScanError());
                    return new ServiceDetail(v,
                            samples.findByHostIdAndNameAndRecordedAtAfterOrderByRecordedAtAsc(hostId, name, now.minus(Duration.ofHours(hours)))
                                    .stream().map(x -> new Sample(x.getRecordedAt(), x.getStatus(), x.getCpuPercent(),
                                            x.getMemoryBytes() == null ? null : x.getMemoryBytes() / 1048576.0, x.getRestarts(),
                                            x.getLatencyMs(), x.getProbeOk(), x.getErrorLines())).toList(),
                            events.serviceEvents(hostId, name, now.minus(Duration.ofDays(7))).stream().map(ApiDtos.EventView::of).toList(),
                            incidents.findByHostIdAndServiceOrderByLastSeenDesc(hostId, name).stream().limit(50).map(IncidentRef::of).toList(),
                            vulns.openFor(hostId, name).stream().map(VulnView::of).toList(),
                            iv);
                });
    }

    private ServiceView view(Host h, Map<String, Object> s, List<Incident> active, Map<String, Long> minRestarts,
                             Map<String, Availability> avail, Instant now) {
        String name = String.valueOf(s.get("name"));
        String status = String.valueOf(s.get("status"));
        long restarts = s.get("restarts") instanceof Number n ? n.longValue() : 0;
        long lastHour = Math.max(0, restarts - minRestarts.getOrDefault(name, restarts));
        long mem = s.get("memoryBytes") instanceof Number n ? n.longValue() : 0;
        long hostMem = h.getMetrics() != null && h.getMetrics().get("memTotalBytes") instanceof Number n ? n.longValue() : 0;
        double memPct = hostMem > 0 ? 100.0 * mem / hostMem : 0;
        double cpu = s.get("cpuPercent") instanceof Number n ? n.doubleValue() : 0;
        Availability av = avail.getOrDefault(name, new Availability(null, null, null, null, 0));

        List<IncidentRef> mine = active.stream()
                .filter(i -> i.getHostId().equals(h.getId()) && name.equals(i.getService()))
                .sorted(Comparator.comparing(Incident::getSeverity).reversed())
                .map(IncidentRef::of).toList();

        Map<Vulnerability.Level, Long> vulnCounts = new EnumMap<>(Vulnerability.Level.class);
        for (Vulnerability.Level l : Vulnerability.Level.values()) {
            vulnCounts.put(l, 0L);
        }
        vulns.openFor(h.getId(), name).stream().filter(v -> !v.isDev()).forEach(v -> vulnCounts.merge(v.getSeverity(), 1L, Long::sum));
        List<ServiceSecurity.Check> checks = ServiceSecurity.checks(s, vulnCounts, vulns.inventory(h.getId(), name).orElse(null),
                av.probeOkPct(), av.errorsLastHour(), now);
        int score = ServiceSecurity.score(checks, vulnCounts);

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
            if (s.get("probe") instanceof Map<?, ?> p && !Boolean.TRUE.equals(p.get("ok"))) {
                health = Health.DEGRADED;
                reasons.add("Não responde na porta " + p.get("port"));
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
            if (av.errorsLastHour() > 100) {
                health = Health.DEGRADED;
                reasons.add(av.errorsLastHour() + " linhas de erro na última hora");
            }
            if (mine.stream().anyMatch(i -> i.severity().atLeast(Severity.HIGH) && !i.ruleId().startsWith("SERVICE_"))) {
                health = Health.DEGRADED;
                reasons.add("Incidente de segurança ligado a este app");
            }
        }
        if (health == Health.HEALTHY && reasons.isEmpty()) {
            reasons.add("Online, respondendo, sem reinícios recentes nem incidentes abertos");
        }
        long total30d = incidents.findByHostIdAndServiceOrderByLastSeenDesc(h.getId(), name).stream()
                .filter(i -> i.getLastSeen().isAfter(now.minus(Duration.ofDays(30)))).count();
        return new ServiceView(h.getId(), hostOnline, h.getLastSeen(), s, health, reasons, lastHour, memPct, mine, total30d,
                score, checks, vulnCounts, av);
    }

    private static long num(Object o) {
        return o instanceof Number n ? n.longValue() : 0;
    }

    private static Double dbl(Object o) {
        return o instanceof Number n ? n.doubleValue() : null;
    }
}
