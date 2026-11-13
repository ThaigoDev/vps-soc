package com.vpssoc.detection.rules;

import com.vpssoc.detection.Detection;
import com.vpssoc.detection.DetectionRule;
import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.EventType;
import com.vpssoc.domain.IncidentStatus;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.IncidentRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Attacks against the web applications, from the access log (the agent aggregates suspicious
 * requests per IP). Scanners looking for {@code /.env} or {@code /wp-login.php} hit every
 * server on the internet all day: they are kept as events (map, top IPs) but do not open an
 * incident. An incident opens when an IP actually tries to exploit the application
 * (SQL injection, path traversal, command injection, Log4Shell, XSS) {@value #MIN_EXPLOITS}
 * times within {@link #WINDOW}, or uses an attack tool (sqlmap, nikto, nuclei...).
 */
@Component
public class WebAttackRule implements DetectionRule {

    static final Duration WINDOW = Duration.ofMinutes(10);
    static final int MIN_EXPLOITS = 3;

    static final Map<String, String> LABELS = Map.of(
            "SQLI", "SQL injection",
            "PATH_TRAVERSAL", "path traversal",
            "COMMAND_INJECTION", "injeção de comando",
            "LOG4SHELL", "Log4Shell (JNDI)",
            "XSS", "XSS",
            "SENSITIVE_FILE", "busca de arquivos sensíveis",
            "ADMIN_PROBE", "busca de painéis/admin");

    private final EventRepository events;
    private final IncidentRepository incidents;

    public WebAttackRule(EventRepository events, IncidentRepository incidents) {
        this.events = events;
        this.incidents = incidents;
    }

    @Override
    public Set<EventType> triggers() {
        return Set.of(EventType.WEB_ATTACK);
    }

    @Override
    public List<Detection> evaluate(SecurityEvent e) {
        String ip = e.getSourceIp();
        if (ip == null) {
            return List.of();
        }
        String host = e.getHostId();
        Detection attach = Detection.attachIfActive(host, RuleIds.WEB_ATTACK, ip).build();
        if (incidents.findFirstByHostIdAndRuleIdAndDedupKeyAndStatusIn(host, RuleIds.WEB_ATTACK, ip, IncidentStatus.ACTIVE).isPresent()) {
            return List.of(attach);
        }

        Instant to = e.getOccurredAt();
        Instant from = to.minus(WINDOW);
        List<SecurityEvent> recent = events.findByHostIdAndSourceIpAndTypeAndOccurredAtBetween(host, ip, EventType.WEB_ATTACK, from, to.plusSeconds(1));
        long requests = 0;
        long exploits = 0;
        long success = 0;
        String tool = null;
        Map<String, Long> categories = new TreeMap<>();
        Set<String> samples = new LinkedHashSet<>();
        List<Long> ids = new ArrayList<>();
        for (SecurityEvent ev : recent) {
            ids.add(ev.getId());
            requests += num(ev.meta("requests"));
            exploits += num(ev.meta("exploitRequests"));
            success += num(ev.meta("successfulRequests"));
            if (ev.meta("tool") instanceof String t && !t.isBlank()) {
                tool = t;
            }
            if (ev.meta("categories") instanceof Map<?, ?> m) {
                m.forEach((k, v) -> categories.merge(String.valueOf(k), num(v), Long::sum));
            }
            if (ev.meta("samples") instanceof List<?> l) {
                l.stream().limit(5 - Math.min(5, samples.size())).forEach(x -> samples.add(String.valueOf(x)));
            }
        }
        if (exploits < MIN_EXPLOITS && tool == null) {
            return List.of(attach);
        }

        List<String> kinds = categories.keySet().stream().map(k -> LABELS.getOrDefault(k, k)).toList();
        boolean exploiting = exploits > 0;
        StringBuilder d = new StringBuilder("%d requisições suspeitas de %s nos últimos %d min nos sites deste servidor (%s)."
                .formatted(requests, ip, WINDOW.toMinutes(), String.join(", ", kinds)));
        if (tool != null) {
            d.append(" Ferramenta de ataque identificada: ").append(tool).append('.');
        }
        if (exploiting && success > 0) {
            d.append(" %d delas tiveram resposta 2xx: confira se a aplicação devolveu dados (sites que respondem 200 para qualquer rota também aparecem aqui).".formatted(success));
        }
        if (!samples.isEmpty()) {
            d.append(" Exemplos: ").append(String.join(" | ", samples));
        }
        List<Long> related = List.copyOf(ids);
        return List.of(Detection.raise(host, RuleIds.WEB_ATTACK, ip)
                .title((exploiting ? "Tentativa de ataque web de " : "Varredura com ferramenta de ataque de ") + ip
                        + (kinds.isEmpty() ? "" : ": " + String.join(", ", kinds.subList(0, Math.min(3, kinds.size())))))
                .description(d.toString())
                .severity(Severity.MEDIUM)
                .risk((int) Math.min(70, 35 + exploits + (tool != null ? 10 : 0)))
                .sourceIp(ip)
                .techniques(exploiting ? new String[]{Mitre.EXPLOIT_PUBLIC_APP, Mitre.VULNERABILITY_SCANNING}
                        : new String[]{Mitre.VULNERABILITY_SCANNING})
                .related(() -> related)
                .build());
    }

    private static long num(Object o) {
        return o instanceof Number n ? n.longValue() : 0;
    }
}
