package com.vpssoc.detection.rules;

import com.vpssoc.config.SocProperties;
import com.vpssoc.detection.Detection;
import com.vpssoc.detection.DetectionRule;
import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.EventType;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import com.vpssoc.repository.EventRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * N SSH authentication failures from one IP inside a sliding window. One incident per attacking
 * IP; while it is active, every further failure from that IP is attached to it.
 */
@Component
public class SshBruteForceRule implements DetectionRule {

    private final EventRepository events;
    private final SocProperties.Detection cfg;

    public SshBruteForceRule(EventRepository events, SocProperties props) {
        this.events = events;
        this.cfg = props.detection();
    }

    @Override
    public Set<EventType> triggers() {
        return EventType.SSH_FAILURES;
    }

    @Override
    public List<Detection> evaluate(SecurityEvent e) {
        String ip = e.getSourceIp();
        if (ip == null) {
            return List.of();
        }
        String host = e.getHostId();
        Instant to = e.getOccurredAt();
        Instant from = to.minus(cfg.bruteForceWindow());
        long failures = events.countByHostIdAndSourceIpAndTypeInAndOccurredAtBetween(host, ip, EventType.SSH_FAILURES, from, to);

        if (failures < cfg.bruteForceThreshold()) {
            return List.of(Detection.attachIfActive(host, RuleIds.SSH_BRUTE_FORCE, ip).build());
        }

        Instant sprayFrom = to.minus(cfg.sprayWindow());
        long users = events.countDistinctUsernames(host, ip, EventType.SSH_FAILURES, sprayFrom, to);
        boolean spraying = users >= cfg.sprayDistinctUsers();

        var d = Detection.raise(host, RuleIds.SSH_BRUTE_FORCE, ip)
                .title("Brute force SSH de " + ip)
                .description("%d falhas de autenticação SSH em %ds vindas de %s%s.".formatted(
                        failures, cfg.bruteForceWindow().toSeconds(), ip,
                        spraying ? " testando %d usuários diferentes (password spraying)".formatted(users) : ""))
                .severity(Severity.MEDIUM)
                .risk((int) Math.min(75, 35 + failures))
                .sourceIp(ip)
                .related(() -> events.findIds(host, ip, EventType.SSH_FAILURES, from, to, PageRequest.of(0, 200)));
        if (spraying) {
            d.techniques(Mitre.BRUTE_FORCE, Mitre.PASSWORD_GUESSING, Mitre.PASSWORD_SPRAYING);
        } else {
            d.techniques(Mitre.BRUTE_FORCE, Mitre.PASSWORD_GUESSING).username(e.getUsername());
        }
        return List.of(d.build());
    }
}
