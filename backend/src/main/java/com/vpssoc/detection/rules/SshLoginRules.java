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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Rules on successful SSH logins:
 * <ul>
 *   <li>login after many failures from the same IP: the brute force worked (CRITICAL);</li>
 *   <li>direct root login (HIGH);</li>
 *   <li>first login ever seen for that user from that IP (MEDIUM).</li>
 * </ul>
 */
@Component
public class SshLoginRules implements DetectionRule {

    private final EventRepository events;
    private final SocProperties.Detection cfg;

    public SshLoginRules(EventRepository events, SocProperties props) {
        this.events = events;
        this.cfg = props.detection();
    }

    @Override
    public Set<EventType> triggers() {
        return Set.of(EventType.SSH_LOGIN_SUCCESS);
    }

    @Override
    public List<Detection> evaluate(SecurityEvent e) {
        String ip = e.getSourceIp();
        String user = e.getUsername();
        String host = e.getHostId();
        if (ip == null || user == null) {
            return List.of();
        }
        List<Detection> out = new ArrayList<>();
        Object method = e.meta("method");

        Instant to = e.getOccurredAt();
        Instant from = to.minus(cfg.compromiseWindow());
        long failures = events.countByHostIdAndSourceIpAndTypeInAndOccurredAtBetween(host, ip, EventType.SSH_FAILURES, from, to);
        if (failures >= cfg.compromiseMinFailures()) {
            // Keyed by user so later sudo activity of that user is correlated into this incident.
            out.add(Detection.raise(host, RuleIds.SSH_COMPROMISE, user)
                    .title("Possível conta comprometida: login de " + user + " após brute force")
                    .description("Login SSH bem-sucedido de %s como '%s' (%s) depois de %d falhas do mesmo IP nos últimos %d min."
                            .formatted(ip, user, method, failures, cfg.compromiseWindow().toMinutes()))
                    .severity(Severity.CRITICAL)
                    .risk(95)
                    .techniques(Mitre.BRUTE_FORCE, Mitre.VALID_ACCOUNTS)
                    .sourceIp(ip)
                    .username(user)
                    .related(() -> events.findIds(host, ip, EventType.SSH_FAILURES, from, to, PageRequest.of(0, 200)))
                    .build());
        }

        if (cfg.trustedSshSource(ip)) {
            // Expected access path (e.g. the provider's web console): logged, not an incident.
            return out;
        }

        if ("root".equals(user)) {
            out.add(Detection.raise(host, RuleIds.SSH_ROOT_LOGIN, ip)
                    .title("Login SSH direto como root de " + ip)
                    .description("Login como root via %s. Prefira PermitRootLogin no e sudo a partir de um usuário comum."
                            .formatted(method))
                    .severity(Severity.HIGH)
                    .risk(70)
                    .techniques(Mitre.LOCAL_ACCOUNTS)
                    .sourceIp(ip)
                    .username(user)
                    .build());
        } else if (!events.existsByHostIdAndTypeAndUsernameAndSourceIpAndIdNot(host, EventType.SSH_LOGIN_SUCCESS, user, ip, e.getId())) {
            out.add(Detection.raise(host, RuleIds.SSH_NEW_SOURCE, user + "@" + ip)
                    .title("Primeiro login de " + user + " a partir de " + ip)
                    .description("Nunca houve login de '%s' vindo de %s. Confirme que foi você.".formatted(user, ip))
                    .severity(Severity.MEDIUM)
                    .risk(35)
                    .techniques(Mitre.VALID_ACCOUNTS)
                    .sourceIp(ip)
                    .username(user)
                    .build());
        }
        return out;
    }
}
