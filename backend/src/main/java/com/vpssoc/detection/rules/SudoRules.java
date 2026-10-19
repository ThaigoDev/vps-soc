package com.vpssoc.detection.rules;

import com.vpssoc.detection.Detection;
import com.vpssoc.detection.DetectionRule;
import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.EventType;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Sudo failures raise their own incident; any sudo activity by a user whose account is in an
 * active compromise incident is correlated into that incident (privilege escalation step).
 */
@Component
public class SudoRules implements DetectionRule {

    @Override
    public Set<EventType> triggers() {
        return Set.of(EventType.SUDO_COMMAND, EventType.SUDO_AUTH_FAILURE, EventType.SUDO_DENIED);
    }

    @Override
    public List<Detection> evaluate(SecurityEvent e) {
        String user = e.getUsername();
        if (user == null) {
            return List.of();
        }
        List<Detection> out = new ArrayList<>();
        out.add(Detection.attachIfActive(e.getHostId(), RuleIds.SSH_COMPROMISE, user)
                .techniques(Mitre.SUDO)
                .risk(100)
                .build());

        if (e.getType() != EventType.SUDO_COMMAND) {
            boolean denied = e.getType() == EventType.SUDO_DENIED;
            out.add(Detection.raise(e.getHostId(), RuleIds.SUDO_FAILURE, user)
                    .title(denied ? "Usuário fora do sudoers tentou usar sudo: " + user
                            : "Falha de senha no sudo: " + user)
                    .description("Comando: %s (como %s)".formatted(e.meta("command"), e.meta("runAs")))
                    .severity(denied ? Severity.HIGH : Severity.MEDIUM)
                    .risk(denied ? 60 : 40)
                    .techniques(Mitre.SUDO)
                    .username(user)
                    .build());
        }
        return out;
    }
}
