package com.vpssoc.ingest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vpssoc.config.SocProperties;
import com.vpssoc.detection.Detection;
import com.vpssoc.detection.DetectionEngine;
import com.vpssoc.detection.PostureEvaluator;
import com.vpssoc.response.ResponseService;
import com.vpssoc.service.ServiceEvaluator;
import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.*;
import com.vpssoc.incident.IncidentService;
import com.vpssoc.ingest.IngestDtos.AgentEvent;
import com.vpssoc.ingest.IngestDtos.Heartbeat;
import com.vpssoc.ingest.IngestDtos.IngestResult;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.HostMetricRepository;
import com.vpssoc.repository.HostRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class IngestService {

    private static final Logger log = LoggerFactory.getLogger(IngestService.class);
    /** Characters of an IPv4/IPv6 literal; anything else is not stored as a source IP. */
    private static final Pattern IP_LITERAL = Pattern.compile("[0-9A-Fa-f:.]{2,45}");
    private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(5);
    private static final int MAX_TEXT = 4000;

    private final HostRepository hosts;
    private final EventRepository events;
    private final HostMetricRepository metrics;
    private final DetectionEngine engine;
    private final IncidentService incidents;
    private final SocProperties props;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final PostureEvaluator posture;
    private final ServiceEvaluator serviceEvaluator;
    private final ResponseService response;

    public IngestService(HostRepository hosts, EventRepository events, HostMetricRepository metrics,
                         DetectionEngine engine, IncidentService incidents, SocProperties props,
                         ObjectMapper mapper, Clock clock, PostureEvaluator posture, ResponseService response,
                         ServiceEvaluator serviceEvaluator) {
        this.serviceEvaluator = serviceEvaluator;
        this.posture = posture;
        this.response = response;
        this.hosts = hosts;
        this.events = events;
        this.metrics = metrics;
        this.engine = engine;
        this.incidents = incidents;
        this.props = props;
        this.mapper = mapper;
        this.clock = clock;
    }

    @Transactional
    public IngestResult ingestEvents(String hostId, List<AgentEvent> batch, String remoteIp) {
        Instant now = clock.instant();
        Host host = touchHost(hostId, remoteIp, now);

        List<SecurityEvent> saved = new ArrayList<>(batch.size());
        int skipped = 0;
        for (AgentEvent in : batch) {
            Optional<EventType> type = EventType.parse(in.type());
            if (type.isEmpty()) {
                skipped++;
                continue;
            }
            saved.add(new SecurityEvent(host.getId(), type.get(), clampTime(in.occurredAt(), now), now,
                    cleanIp(in.sourceIp()), truncate(in.username(), 255), truncate(in.message(), MAX_TEXT), in.metadata()));
        }
        events.saveAll(saved);
        for (SecurityEvent e : saved) {
            engine.process(e);
            if (e.getType() == EventType.RESPONSE_EXECUTED) {
                response.recordAgentAction(e);
            }
        }
        if (skipped > 0) {
            log.warn("Host {} sent {} events of unknown type", hostId, skipped);
        }
        return new IngestResult(saved.size(), skipped);
    }

    @Transactional
    public void heartbeat(Heartbeat hb, String remoteIp) {
        Instant now = clock.instant();
        Host host = touchHost(hb.hostId(), remoteIp, now);
        host.setHostname(truncate(hb.hostname(), 255));
        host.setOs(truncate(hb.os(), 255));
        host.setAgentVersion(truncate(hb.agentVersion(), 50));
        if (hb.heartbeatIntervalSeconds() != null && hb.heartbeatIntervalSeconds() > 0) {
            host.setHeartbeatIntervalSeconds(hb.heartbeatIntervalSeconds());
        }
        host.setOpenPorts(hb.openPorts());
        host.setPosture(hb.posture());
        host.setResponse(hb.response());
        if (hb.services() != null) {
            host.setServices(hb.services());
        }
        host.setPm2(hb.pm2());

        var m = hb.metrics();
        if (m != null) {
            host.setMetrics(mapper.convertValue(m, new TypeReference<Map<String, Object>>() {
            }));
            metrics.save(new HostMetric(host.getId(), now, m.cpuPercent(), m.memPercent(), m.diskPercent(), m.load1())
                    .withExtras(m.swapPercent(), m.netRxBps(), m.netTxBps(), m.tcpEstablished(), m.processes()));
            checkDisk(host, m.diskPercent());
        }
        posture.evaluate(host.getId(), hb.posture());
        serviceEvaluator.evaluate(host, hb.services(), m == null ? null : m.memTotalBytes(), now);
    }

    private Host touchHost(String hostId, String remoteIp, Instant now) {
        Host host = hosts.findById(hostId).orElseGet(() -> {
            log.info("New host registered: {} from {}", hostId, remoteIp);
            return hosts.save(new Host(hostId, now));
        });
        host.setLastSeen(now);
        host.setLastIp(remoteIp);
        if (host.getStatus() == HostStatus.OFFLINE) {
            host.setStatus(HostStatus.ONLINE);
            incidents.resolveActive(hostId, RuleIds.AGENT_OFFLINE, hostId, "Agente voltou a reportar em " + now);
        }
        return host;
    }

    private void checkDisk(Host host, Double diskPercent) {
        if (diskPercent == null) {
            return;
        }
        double limit = props.detection().diskUsagePercent();
        if (diskPercent >= limit) {
            incidents.apply(Detection.raise(host.getId(), RuleIds.DISK_USAGE_HIGH, "/")
                    .title("Disco quase cheio em %s: %.1f%%".formatted(host.getId(), diskPercent))
                    .description("Uso da partição / acima de %.0f%%. Disco cheio para logs e serviços.".formatted(limit))
                    .severity(diskPercent >= 97 ? Severity.HIGH : Severity.MEDIUM)
                    .risk(diskPercent >= 97 ? 60 : 30)
                    .build(), null);
        } else if (diskPercent < limit - 2) { // small hysteresis to avoid flapping
            incidents.resolveActive(host.getId(), RuleIds.DISK_USAGE_HIGH, "/", "Uso de disco voltou para %.1f%%".formatted(diskPercent));
        }
    }

    /** Uses the agent's timestamp, unless it is missing or too far in the future. */
    private static Instant clampTime(Instant occurredAt, Instant now) {
        if (occurredAt == null || occurredAt.isAfter(now.plus(MAX_CLOCK_SKEW))) {
            return now;
        }
        return occurredAt;
    }

    private static String cleanIp(String ip) {
        return ip != null && IP_LITERAL.matcher(ip).matches() ? ip : null;
    }

    private static String truncate(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }
}
