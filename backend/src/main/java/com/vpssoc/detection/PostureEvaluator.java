package com.vpssoc.detection;

import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.Incident;
import com.vpssoc.domain.IncidentStatus;
import com.vpssoc.domain.Severity;
import com.vpssoc.incident.IncidentService;
import com.vpssoc.repository.IncidentRepository;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Turns the hardening state the agent reports with each heartbeat into findings: failed
 * services, pending security patches, a pending reboot, SSH accepting passwords or root.
 * Each finding resolves itself when the condition clears. Marking one as a false positive
 * means "accepted risk": it is not raised again while the condition stays the same.
 */
@Component
public class PostureEvaluator {

    private final IncidentService incidents;
    private final IncidentRepository repo;

    public PostureEvaluator(IncidentService incidents, IncidentRepository repo) {
        this.incidents = incidents;
        this.repo = repo;
    }

    public void evaluate(String hostId, Map<String, Object> posture) {
        if (posture == null) {
            return;
        }
        failedServices(hostId, posture.get("failedUnits"));
        updates(hostId, posture);
        reboot(hostId, posture.get("rebootRequired"));
        ssh(hostId, posture.get("ssh"));
        certificates(hostId, posture.get("certificates"));
    }

    /** TLS certificates (certbot and nginx): expiring in 14 days or less, or already expired. */
    private void certificates(String hostId, Object v) {
        if (!(v instanceof List<?> list)) {
            return;
        }
        java.time.Instant now = java.time.Instant.now();
        Set<String> seen = new HashSet<>();
        for (Object o : list) {
            if (!(o instanceof Map<?, ?> c) || c.get("notAfter") == null || c.get("path") == null) {
                continue;
            }
            String path = c.get("path").toString();
            seen.add(path);
            java.time.Instant notAfter;
            try {
                notAfter = java.time.Instant.parse(c.get("notAfter").toString());
            } catch (java.time.format.DateTimeParseException e) {
                continue;
            }
            long days = java.time.Duration.between(now, notAfter).toDays();
            String names = c.get("dnsNames") instanceof List<?> dn && !dn.isEmpty()
                    ? String.join(", ", dn.stream().map(String::valueOf).toList()) : String.valueOf(c.get("subject"));
            if (days > 14) {
                incidents.resolveActive(hostId, RuleIds.CERT_EXPIRING, path, "Certificado renovado: vale até " + notAfter);
                continue;
            }
            boolean expired = notAfter.isBefore(now);
            raise(Detection.raise(hostId, RuleIds.CERT_EXPIRING, path)
                    .title(expired ? "Certificado TLS vencido: " + names : "Certificado TLS vence em %d dia(s): %s".formatted(days, names))
                    .description("O certificado %s (%s, emitido por %s) %s em %s."
                            .formatted(path, names, c.get("issuer"), expired ? "venceu" : "vence", notAfter))
                    .severity(expired || days <= 3 ? Severity.HIGH : Severity.MEDIUM)
                    .risk(expired ? 70 : days <= 3 ? 60 : 35)
                    .build());
        }
        for (Incident open : repo.findByHostIdAndRuleIdAndStatusIn(hostId, RuleIds.CERT_EXPIRING, IncidentStatus.ACTIVE)) {
            if (!seen.contains(open.getDedupKey())) {
                incidents.resolveActive(hostId, RuleIds.CERT_EXPIRING, open.getDedupKey(), "O certificado não está mais em uso");
            }
        }
    }

    private void failedServices(String hostId, Object v) {
        if (!(v instanceof List<?> list)) {
            return;
        }
        Set<String> failed = new LinkedHashSet<>();
        list.stream().map(String::valueOf).filter(u -> u.endsWith(".service")).forEach(failed::add);
        for (Incident open : repo.findByHostIdAndRuleIdAndStatusIn(hostId, RuleIds.SERVICE_FAILED, IncidentStatus.ACTIVE)) {
            if (!failed.contains(open.getDedupKey())) {
                incidents.resolveActive(hostId, RuleIds.SERVICE_FAILED, open.getDedupKey(), "O serviço voltou a rodar");
            }
        }
        for (String unit : failed) {
            raise(Detection.raise(hostId, RuleIds.SERVICE_FAILED, unit)
                    .title("Serviço em falha: " + unit)
                    .description("O systemd marcou %s como failed: o processo terminou com erro e não está rodando.".formatted(unit))
                    .severity(Severity.MEDIUM)
                    .risk(35)
                    .build());
        }
    }

    private void updates(String hostId, Map<String, Object> posture) {
        int security = intOf(posture.get("securityUpdates"));
        int pending = intOf(posture.get("pendingUpdates"));
        if (security < 0) {
            return; // not an Ubuntu host, or update-notifier not installed
        }
        if (security == 0) {
            incidents.resolveActive(hostId, RuleIds.SECURITY_UPDATES, "apt", "Não há mais atualizações de segurança pendentes");
            return;
        }
        raise(Detection.raise(hostId, RuleIds.SECURITY_UPDATES, "apt")
                .title("%d atualizaç%s de segurança pendente%s".formatted(security, security == 1 ? "ão" : "ões", security == 1 ? "" : "s"))
                .description("%d pacotes com correções de segurança aguardam instalação (%d atualizações no total).".formatted(security, pending))
                .severity(security >= 10 ? Severity.MEDIUM : Severity.LOW)
                .risk(Math.min(50, 15 + security * 2))
                .techniques(Mitre.EXPLOIT_PUBLIC_APP)
                .build());
    }

    private void reboot(String hostId, Object v) {
        if (Boolean.TRUE.equals(v)) {
            raise(Detection.raise(hostId, RuleIds.REBOOT_REQUIRED, "kernel")
                    .title("Reinicialização pendente em " + hostId)
                    .description("Atualizações já instaladas (normalmente kernel ou libc) só passam a valer depois de reiniciar.")
                    .severity(Severity.LOW)
                    .risk(15)
                    .build());
        } else if (Boolean.FALSE.equals(v)) {
            incidents.resolveActive(hostId, RuleIds.REBOOT_REQUIRED, "kernel", "Servidor reiniciado");
        }
    }

    private void ssh(String hostId, Object v) {
        if (!(v instanceof Map<?, ?> ssh)) {
            return;
        }
        String password = String.valueOf(ssh.get("passwordAuthentication"));
        String root = String.valueOf(ssh.get("permitRootLogin"));
        List<String> problems = new ArrayList<>();
        if ("yes".equals(password)) {
            problems.add("PasswordAuthentication yes (aceita login por senha, alvo de brute force)");
        }
        if ("yes".equals(root)) {
            problems.add("PermitRootLogin yes (root pode entrar com senha)");
        }
        if (problems.isEmpty()) {
            incidents.resolveActive(hostId, RuleIds.SSH_WEAK_CONFIG, "sshd", "Configuração do SSH endurecida");
            return;
        }
        raise(Detection.raise(hostId, RuleIds.SSH_WEAK_CONFIG, "sshd")
                .title("SSH aceita " + ("yes".equals(password) ? "login por senha" : "root com senha"))
                .description("Configuração efetiva do sshd (sshd -T): " + String.join("; ", problems) + ".")
                .severity(Severity.MEDIUM)
                .risk("yes".equals(password) && "yes".equals(root) ? 50 : 35)
                .techniques(Mitre.BRUTE_FORCE)
                .build());
    }

    /** Raises unless the operator already accepted this exact finding as a false positive. */
    private void raise(Detection d) {
        Optional<Incident> last = repo.findFirstByHostIdAndRuleIdAndDedupKeyOrderByIdDesc(d.hostId(), d.ruleId(), d.dedupKey());
        if (last.isPresent() && last.get().getStatus() == IncidentStatus.FALSE_POSITIVE) {
            return;
        }
        incidents.apply(d, null);
    }

    private static int intOf(Object v) {
        return v instanceof Number n ? n.intValue() : -1;
    }
}
