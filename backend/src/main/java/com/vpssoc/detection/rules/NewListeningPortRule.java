package com.vpssoc.detection.rules;

import com.vpssoc.detection.Detection;
import com.vpssoc.detection.DetectionRule;
import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.EventType;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * A port started listening that was not in the previous snapshot. Binaries running from
 * world-writable temp dirs are a classic sign of a dropped payload / reverse shell listener.
 * A new port during an active compromise incident is also correlated into it.
 */
@Component
public class NewListeningPortRule implements DetectionRule {

    private static final List<String> SUSPICIOUS_DIRS = List.of("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/");

    @Override
    public Set<EventType> triggers() {
        return Set.of(EventType.PORT_OPENED);
    }

    @Override
    public List<Detection> evaluate(SecurityEvent e) {
        Object port = e.meta("port");
        Object address = e.meta("address");
        String process = String.valueOf(e.meta("process"));
        String exe = e.meta("exe") == null ? "" : e.meta("exe").toString();
        boolean suspicious = SUSPICIOUS_DIRS.stream().anyMatch(exe::startsWith) || exe.endsWith(" (deleted)");
        boolean publicBind = "0.0.0.0".equals(address) || "::".equals(address);

        Severity severity = suspicious ? Severity.CRITICAL : publicBind ? Severity.MEDIUM : Severity.LOW;
        int risk = suspicious ? 90 : publicBind ? 45 : 20;

        var raise = Detection.raise(e.getHostId(), RuleIds.NEW_LISTENING_PORT, e.meta("proto") + "/" + address + "/" + port)
                .title("Nova porta em escuta: %s (%s)".formatted(port, process))
                .description("%s:%s aberta por %s (pid %s, exe %s, usuário %s).%s".formatted(
                        address, port, process, e.meta("pid"), exe.isEmpty() ? "?" : exe, e.getUsername(),
                        suspicious ? " O executável roda de um diretório temporário ou foi apagado do disco." : ""))
                .severity(severity)
                .risk(risk)
                .username(e.getUsername());
        if (suspicious) {
            raise.techniques(Mitre.NON_STANDARD_PORT, Mitre.COMMAND_INTERPRETER);
        } else {
            raise.techniques(Mitre.NON_STANDARD_PORT);
        }

        return List.of(
                raise.build(),
                Detection.attachIfActive(e.getHostId(), RuleIds.SSH_COMPROMISE, null)
                        .techniques(Mitre.NON_STANDARD_PORT)
                        .risk(100)
                        .build());
    }
}
