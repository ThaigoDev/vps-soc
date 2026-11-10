package com.vpssoc.detection.rules;

import com.vpssoc.detection.Detection;
import com.vpssoc.detection.DetectionRule;
import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.EventType;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import com.vpssoc.service.ServiceDirectory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * Suspicious processes found by the agent's /proc scan:
 * <ul>
 *   <li>WEB_SHELL: sh/bash/dash spawned by nginx/apache/php-fpm/node/java or running as www-data (CRITICAL);</li>
 *   <li>TEMP_EXE: binary running from /tmp, /var/tmp or /dev/shm (CRITICAL);</li>
 *   <li>DELETED_EXE: binary deleted from disk. A memfd or temp path is fileless malware (CRITICAL); a
 *       deleted system binary is usually a package upgrade without a service restart (LOW).</li>
 * </ul>
 * Anything but the benign upgrade case is also correlated into an active compromise incident.
 */
@Component
public class SuspiciousProcessRule implements DetectionRule {

    private final ServiceDirectory services;

    public SuspiciousProcessRule(ServiceDirectory services) {
        this.services = services;
    }

    private static final List<String> TEMP_DIRS = List.of("/tmp/", "/var/tmp/", "/dev/shm/");

    @Override
    public Set<EventType> triggers() {
        return Set.of(EventType.PROCESS_SUSPICIOUS);
    }

    @Override
    public List<Detection> evaluate(SecurityEvent e) {
        String reason = String.valueOf(e.meta("reason"));
        String exe = e.meta("exe") == null ? "" : e.meta("exe").toString();
        String path = exe.endsWith(" (deleted)") ? exe.substring(0, exe.length() - " (deleted)".length()) : exe;
        String comm = String.valueOf(e.meta("comm"));
        String parent = String.valueOf(e.meta("parentComm"));
        String host = e.getHostId();
        String where = "pid %s, usuário %s, pai %s (pid %s). Comando: %s".formatted(
                e.meta("pid"), e.getUsername(), parent, e.meta("ppid"), e.meta("cmdline"));

        Detection.Builder raise;
        String[] techniques;
        switch (reason) {
            case "WEB_SHELL" -> {
                techniques = new String[]{Mitre.WEB_SHELL, Mitre.UNIX_SHELL};
                raise = Detection.raise(host, RuleIds.WEB_SHELL, parent)
                        .title("Shell iniciado por serviço web: %s → %s".formatted(parent, comm))
                        .description("Um shell rodando sob um servidor web/aplicação indica web shell ou RCE. " + where)
                        .severity(Severity.CRITICAL)
                        .risk(95);
            }
            case "TEMP_EXE" -> {
                techniques = new String[]{Mitre.COMMAND_INTERPRETER};
                raise = Detection.raise(host, RuleIds.SUSPICIOUS_PROCESS, path)
                        .title("Processo executando de diretório temporário: " + path)
                        .description("Binários em /tmp, /var/tmp ou /dev/shm são típicos de payloads baixados por um atacante. " + where)
                        .severity(Severity.CRITICAL)
                        .risk(90);
            }
            case "DELETED_EXE" -> {
                boolean fileless = path.startsWith("/memfd:") || TEMP_DIRS.stream().anyMatch(path::startsWith);
                if (!fileless) {
                    return List.of(Detection.raise(host, RuleIds.SUSPICIOUS_PROCESS, path)
                            .title("Processo com binário removido do disco: " + comm)
                            .description("%s foi apagado ou substituído enquanto roda, normalmente um pacote atualizado sem reiniciar o serviço. %s"
                                    .formatted(path, where))
                            .severity(Severity.LOW)
                            .risk(15)
                            .username(e.getUsername())
                            .build());
                }
                techniques = new String[]{Mitre.FILE_DELETION, Mitre.COMMAND_INTERPRETER};
                raise = Detection.raise(host, RuleIds.SUSPICIOUS_PROCESS, path)
                        .title("Processo sem arquivo (fileless): " + comm)
                        .description("O binário %s não existe mais no disco (memfd ou apagado de diretório temporário). %s"
                                .formatted(exe, where))
                        .severity(Severity.CRITICAL)
                        .risk(90);
            }
            default -> {
                return List.of();
            }
        }
        return List.of(
                raise.techniques(techniques).username(e.getUsername())
                        // a web shell's parent is the app that was exploited
                        .service(services.nameForPid(host, e.meta("pid"), e.meta("ppid")).orElse(null)).build(),
                Detection.attachIfActive(host, RuleIds.SSH_COMPROMISE, null)
                        .techniques(techniques)
                        .risk(100)
                        .build());
    }
}
