package com.vpssoc.jobs;

import com.vpssoc.config.SocProperties;
import com.vpssoc.detection.Detection;
import com.vpssoc.detection.Mitre;
import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.Host;
import com.vpssoc.domain.HostStatus;
import com.vpssoc.domain.Severity;
import com.vpssoc.incident.IncidentService;
import com.vpssoc.repository.HostRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * An agent that stops reporting is itself a security signal: an attacker with root will
 * usually kill monitoring first. Missing heartbeats raise an incident that is resolved
 * automatically when the agent reports again.
 */
@Component
public class AgentWatchdog {

    private final HostRepository hosts;
    private final IncidentService incidents;
    private final SocProperties.Detection cfg;
    private final Clock clock;

    public AgentWatchdog(HostRepository hosts, IncidentService incidents, SocProperties props, Clock clock) {
        this.hosts = hosts;
        this.incidents = incidents;
        this.cfg = props.detection();
        this.clock = clock;
    }

    @Scheduled(fixedDelay = 30_000, initialDelay = 30_000)
    @Transactional
    public void checkHeartbeats() {
        Instant now = clock.instant();
        for (Host host : hosts.findByStatus(HostStatus.ONLINE)) {
            Duration allowed = Duration.ofSeconds((long) host.getHeartbeatIntervalSeconds() * cfg.offlineMissedHeartbeats());
            if (host.getLastSeen().plus(allowed).isBefore(now)) {
                host.setStatus(HostStatus.OFFLINE);
                incidents.apply(Detection.raise(host.getId(), RuleIds.AGENT_OFFLINE, host.getId())
                        .title("Agente parou de reportar: " + host.getId())
                        .description("Último contato em %s. Pode ser queda da VPS, da rede, ou o agente foi parado/removido."
                                .formatted(host.getLastSeen()))
                        .severity(Severity.HIGH)
                        .risk(60)
                        .techniques(Mitre.DISABLE_TOOLS)
                        .build(), null);
            }
        }
    }
}
