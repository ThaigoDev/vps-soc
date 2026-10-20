package com.vpssoc.service;

import com.vpssoc.config.SocProperties;
import com.vpssoc.detection.Detection;
import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.Host;
import com.vpssoc.domain.Incident;
import com.vpssoc.domain.IncidentStatus;
import com.vpssoc.domain.ServiceSample;
import com.vpssoc.domain.Severity;
import com.vpssoc.incident.IncidentService;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.IncidentRepository;
import com.vpssoc.repository.ServiceSampleRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Runs on every heartbeat with the PM2 list: records a sample per app, raises
 * SERVICE_DOWN / SERVICE_HIGH_MEMORY from the current state, and resolves the service
 * incidents whose condition has cleared (back online, no restarts for 15 min, memory down,
 * app removed from PM2).
 */
@Component
public class ServiceEvaluator {

    static final Duration LOOP_QUIET = Duration.ofMinutes(15);

    private final ServiceSampleRepository samples;
    private final IncidentService incidents;
    private final IncidentRepository incidentRepo;
    private final EventRepository events;
    private final SocProperties props;

    public ServiceEvaluator(ServiceSampleRepository samples, IncidentService incidents, IncidentRepository incidentRepo,
                            EventRepository events, SocProperties props) {
        this.samples = samples;
        this.incidents = incidents;
        this.incidentRepo = incidentRepo;
        this.events = events;
        this.props = props;
    }

    public void evaluate(Host host, List<Map<String, Object>> services, Long memTotalBytes, Instant now) {
        if (services == null) {
            return; // older agent, or PM2 unreadable this time: keep the last known state
        }
        String hostId = host.getId();
        Map<String, List<Map<String, Object>>> byName = new LinkedHashMap<>();
        for (Map<String, Object> s : services) {
            String name = String.valueOf(s.get("name"));
            byName.computeIfAbsent(name, k -> new ArrayList<>()).add(s);
            Map<?, ?> probe = s.get("probe") instanceof Map<?, ?> p ? p : null;
            samples.save(new ServiceSample(hostId, name, intOrNull(s.get("pmId")), now, String.valueOf(s.get("status")),
                    dbl(s.get("cpuPercent")), lng(s.get("memoryBytes")), intOrNull(s.get("restarts")))
                    .withHealth(probe == null ? null : Boolean.TRUE.equals(probe.get("ok")),
                            probe == null ? null : intOrNull(probe.get("status")),
                            probe == null ? null : intOrNull(probe.get("latencyMs")),
                            intOrNull(s.get("errorLines"))));
        }

        for (var entry : byName.entrySet()) {
            String name = entry.getKey();
            List<Map<String, Object>> inst = entry.getValue();
            Optional<String> bad = inst.stream().map(s -> String.valueOf(s.get("status")))
                    .filter(st -> st.equals("errored") || st.equals("stopped")).findFirst();
            if (bad.isPresent()) {
                Detection d = com.vpssoc.detection.rules.ServiceRules.down(hostId, name, bad.get(), null);
                if (!"stopped".equals(bad.get()) || !acceptedRisk(hostId, RuleIds.SERVICE_DOWN, name)) {
                    incidents.apply(d, null);
                }
            } else if (inst.stream().allMatch(s -> "online".equals(s.get("status")))) {
                incidents.resolveActive(hostId, RuleIds.SERVICE_DOWN, name, "O app voltou a ficar online no PM2");
            }

            if (events.sumServiceRestarts(hostId, name, now.minus(LOOP_QUIET)) == 0) {
                incidents.resolveActive(hostId, RuleIds.SERVICE_CRASH_LOOP, name,
                        "Nenhum reinício nos últimos %d minutos".formatted(LOOP_QUIET.toMinutes()));
            }

            memory(hostId, name, inst, memTotalBytes);
            debugger(hostId, name, inst);
            responding(hostId, name, inst);
        }

        // Apps deleted from PM2 take their open incidents with them.
        for (Incident inc : incidentRepo.findByHostIdAndRuleIdAndStatusIn(hostId, RuleIds.SERVICE_DOWN, IncidentStatus.ACTIVE)) {
            closeIfGone(inc, byName.keySet());
        }
        for (Incident inc : incidentRepo.findByHostIdAndRuleIdAndStatusIn(hostId, RuleIds.SERVICE_CRASH_LOOP, IncidentStatus.ACTIVE)) {
            closeIfGone(inc, byName.keySet());
        }
        for (String rule : List.of(RuleIds.SERVICE_HIGH_MEMORY, RuleIds.SERVICE_DEBUG_EXPOSED, RuleIds.SERVICE_NOT_RESPONDING)) {
            for (Incident inc : incidentRepo.findByHostIdAndRuleIdAndStatusIn(hostId, rule, IncidentStatus.ACTIVE)) {
                closeIfGone(inc, byName.keySet());
            }
        }
    }

    private void memory(String hostId, String name, List<Map<String, Object>> inst, Long memTotal) {
        if (memTotal == null || memTotal <= 0) {
            return;
        }
        long used = inst.stream().mapToLong(s -> Optional.ofNullable(lng(s.get("memoryBytes"))).orElse(0L)).sum();
        double pct = 100.0 * used / memTotal;
        double limit = props.response().serviceMemoryPercent();
        if (pct >= limit) {
            incidents.apply(Detection.raise(hostId, RuleIds.SERVICE_HIGH_MEMORY, name)
                    .title("App PM2 usando %.0f%% da RAM: %s".formatted(pct, name))
                    .description("%s está com %d MB de memória (%.1f%% da RAM do servidor, limite %.0f%%)."
                            .formatted(name, used / (1024 * 1024), pct, limit))
                    .severity(Severity.MEDIUM)
                    .risk((int) Math.min(60, 20 + pct / 2))
                    .service(name)
                    .build(), null);
        } else if (pct < limit - 5) {
            incidents.resolveActive(hostId, RuleIds.SERVICE_HIGH_MEMORY, name,
                    "Uso de memória voltou para %.1f%% da RAM".formatted(pct));
        }
    }

    /** Node's inspector lets whoever reaches the port run arbitrary code in the app. */
    private void debugger(String hostId, String name, List<Map<String, Object>> inst) {
        Optional<String> flag = inst.stream()
                .map(s -> s.get("security") instanceof Map<?, ?> sec ? sec.get("inspect") : null)
                .filter(f -> f != null && !f.toString().isBlank()).map(Object::toString).findFirst();
        if (flag.isEmpty()) {
            incidents.resolveActive(hostId, RuleIds.SERVICE_DEBUG_EXPOSED, name, "O app não roda mais com --inspect");
            return;
        }
        boolean remote = flag.get().contains("0.0.0.0") || flag.get().matches(".*=\\d+\\.\\d+\\.\\d+\\.\\d+:.*") && !flag.get().contains("127.0.0.1");
        incidents.apply(Detection.raise(hostId, RuleIds.SERVICE_DEBUG_EXPOSED, name)
                .title("Debugger do Node aberto em " + name + " (" + flag.get() + ")")
                .description("O app roda com %s. Quem alcançar a porta do inspector pode executar qualquer código dentro do app%s."
                        .formatted(flag.get(), remote ? ", e ela escuta em todas as interfaces" : ""))
                .severity(remote ? Severity.CRITICAL : Severity.HIGH)
                .risk(remote ? 95 : 70)
                .techniques(com.vpssoc.detection.Mitre.EXPLOIT_PUBLIC_APP, com.vpssoc.detection.Mitre.COMMAND_INTERPRETER)
                .service(name)
                .build(), null);
    }

    /** Online in PM2 but not answering on its port for two heartbeats in a row. */
    private void responding(String hostId, String name, List<Map<String, Object>> inst) {
        boolean online = inst.stream().allMatch(s -> "online".equals(s.get("status")));
        List<Map<?, ?>> probes = new ArrayList<>();
        for (Map<String, Object> s : inst) {
            if (s.get("probe") instanceof Map<?, ?> p) {
                probes.add(p);
            }
        }
        if (!online || probes.isEmpty()) {
            return;
        }
        if (probes.stream().anyMatch(p -> Boolean.TRUE.equals(p.get("ok")))) {
            incidents.resolveActive(hostId, RuleIds.SERVICE_NOT_RESPONDING, name, "O app voltou a responder na porta");
            return;
        }
        List<ServiceSample> last = samples.findTop2ByHostIdAndNameOrderByRecordedAtDesc(hostId, name);
        if (last.size() < 2 || !last.stream().allMatch(x -> Boolean.FALSE.equals(x.getProbeOk()))) {
            return; // a single failed check is not an outage
        }
        Map<?, ?> p = probes.getFirst();
        incidents.apply(Detection.raise(hostId, RuleIds.SERVICE_NOT_RESPONDING, name)
                .title("App PM2 não responde: " + name)
                .description("O PM2 mostra %s online, mas a porta %s não responde (%s). O processo está vivo e travado ou quebrado."
                        .formatted(name, p.get("port"), p.get("error") != null ? p.get("error") : "HTTP " + p.get("status")))
                .severity(Severity.HIGH)
                .risk(60)
                .service(name)
                .build(), null);
    }

    private void closeIfGone(Incident inc, Set<String> present) {
        if (!present.contains(inc.getDedupKey())) {
            incidents.resolveActive(inc.getHostId(), inc.getRuleId(), inc.getDedupKey(), "O app foi removido do PM2");
        }
    }

    /** The operator marked this exact finding as a false positive: a deliberate `pm2 stop`. */
    private boolean acceptedRisk(String hostId, String ruleId, String key) {
        return incidentRepo.findFirstByHostIdAndRuleIdAndDedupKeyOrderByIdDesc(hostId, ruleId, key)
                .map(i -> i.getStatus() == IncidentStatus.FALSE_POSITIVE)
                .orElse(false);
    }

    private static Integer intOrNull(Object o) {
        return o instanceof Number n ? n.intValue() : null;
    }

    private static Long lng(Object o) {
        return o instanceof Number n ? n.longValue() : null;
    }

    private static Double dbl(Object o) {
        return o instanceof Number n ? n.doubleValue() : null;
    }
}
