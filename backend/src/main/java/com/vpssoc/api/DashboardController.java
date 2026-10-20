package com.vpssoc.api;

import com.vpssoc.api.ApiDtos.*;
import com.vpssoc.domain.*;
import com.vpssoc.incident.IncidentService;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.HostMetricRepository;
import com.vpssoc.repository.HostRepository;
import com.vpssoc.repository.IncidentRepository;
import com.vpssoc.incident.IncidentNotFoundException;
import com.vpssoc.insight.InsightService;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.web.bind.annotation.*;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** Read/triage API for the dashboard (authenticated with the dashboard token). */
@RestController
@RequestMapping("/api/v1")
public class DashboardController {

    private final DashboardService dashboard;
    private final IncidentService incidentService;
    private final IncidentRepository incidents;
    private final EventRepository events;
    private final HostRepository hosts;
    private final HostMetricRepository metrics;
    private final Clock clock;
    private final InsightService insights;

    public DashboardController(DashboardService dashboard, IncidentService incidentService, IncidentRepository incidents,
                               EventRepository events, HostRepository hosts, HostMetricRepository metrics, Clock clock,
                               InsightService insights) {
        this.insights = insights;
        this.dashboard = dashboard;
        this.incidentService = incidentService;
        this.incidents = incidents;
        this.events = events;
        this.hosts = hosts;
        this.metrics = metrics;
        this.clock = clock;
    }

    @GetMapping("/auth/check")
    public Map<String, Boolean> authCheck() {
        return Map.of("ok", true);
    }

    @GetMapping("/dashboard/summary")
    public Summary summary() {
        return dashboard.summary();
    }

    @GetMapping("/dashboard/timeline")
    public List<TimelineBucket> timeline(@RequestParam(defaultValue = "24") int hours) {
        return dashboard.timeline(Math.clamp(hours, 1, 24 * 7));
    }

    @GetMapping("/dashboard/kpis")
    public ApiDtos.Kpis kpis(@RequestParam(defaultValue = "30") int days) {
        return dashboard.kpis(Math.clamp(days, 1, 365));
    }

    @GetMapping("/dashboard/top-ips")
    public List<SourceIpStats> topIps(@RequestParam(defaultValue = "24") int hours,
                                      @RequestParam(defaultValue = "10") int limit) {
        return dashboard.topSourceIps(Math.clamp(hours, 1, 24 * 30), Math.clamp(limit, 1, 100));
    }

    @GetMapping("/incidents")
    public PageResponse<IncidentView> incidents(@RequestParam(required = false) List<IncidentStatus> status,
                                                @RequestParam(required = false) Severity severity,
                                                @RequestParam(defaultValue = "0") int page,
                                                @RequestParam(defaultValue = "25") int size) {
        Specification<Incident> spec = (root, q, cb) -> cb.conjunction();
        if (status != null && !status.isEmpty()) {
            spec = spec.and((root, q, cb) -> root.get("status").in(status));
        }
        if (severity != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("severity"), severity));
        }
        var pageable = PageRequest.of(Math.max(page, 0), Math.clamp(size, 1, 200), Sort.by(Sort.Direction.DESC, "lastSeen"));
        return PageResponse.of(incidents.findAll(spec, pageable), IncidentView::of);
    }

    @GetMapping("/incidents/{id}")
    public IncidentDetail incident(@PathVariable long id) {
        Incident inc = incidents.findById(id).orElseThrow(() -> new IncidentNotFoundException(id));
        InsightService.Insight in = insights.insight(inc);
        return new IncidentDetail(IncidentView.of(inc), in.events().stream().map(EventView::of).toList(), in.explanation(),
                in.ip(), in.actions().stream().map(ActionView::of).toList());
    }

    @PatchMapping("/incidents/{id}")
    public IncidentView changeStatus(@PathVariable long id, @RequestBody StatusChange change) {
        if (change.status() == null) {
            throw new IllegalArgumentException("status is required");
        }
        return IncidentView.of(incidentService.changeStatus(id, change.status(), change.note()));
    }

    @GetMapping("/events")
    public PageResponse<EventView> events(@RequestParam(required = false) EventType type,
                                          @RequestParam(required = false) EventType.Category category,
                                          @RequestParam(required = false) String ip,
                                          @RequestParam(required = false) String username,
                                          @RequestParam(required = false) String hostId,
                                          @RequestParam(defaultValue = "0") int page,
                                          @RequestParam(defaultValue = "50") int size) {
        Specification<SecurityEvent> spec = (root, q, cb) -> cb.conjunction();
        if (type != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("type"), type));
        }
        if (category != null) {
            List<EventType> types = java.util.Arrays.stream(EventType.values()).filter(t -> t.category() == category).toList();
            spec = spec.and((root, q, cb) -> root.get("type").in(types));
        }
        if (ip != null && !ip.isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("sourceIp"), ip.trim()));
        }
        if (username != null && !username.isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("username"), username.trim()));
        }
        if (hostId != null && !hostId.isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("hostId"), hostId.trim()));
        }
        var pageable = PageRequest.of(Math.max(page, 0), Math.clamp(size, 1, 200),
                Sort.by(Sort.Direction.DESC, "occurredAt").and(Sort.by(Sort.Direction.DESC, "id")));
        return PageResponse.of(events.findAll(spec, pageable), EventView::of);
    }

    @GetMapping("/hosts")
    public List<HostView> hosts() {
        return hosts.findAllByOrderByIdAsc().stream().map(HostView::of).toList();
    }

    @GetMapping("/hosts/{id}/metrics")
    public List<MetricPoint> hostMetrics(@PathVariable String id, @RequestParam(defaultValue = "24") int hours) {
        var since = clock.instant().minus(Duration.ofHours(Math.clamp(hours, 1, 24 * 7)));
        return metrics.findByHostIdAndRecordedAtAfterOrderByRecordedAtAsc(id, since).stream().map(MetricPoint::of).toList();
    }
}
