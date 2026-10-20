package com.vpssoc.response;

import com.vpssoc.config.SocProperties;
import com.vpssoc.config.SocProperties.Policy;
import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.EventType;
import com.vpssoc.domain.Incident;
import com.vpssoc.domain.ResponseAction.Type;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import com.vpssoc.incident.IncidentChanged;
import com.vpssoc.repository.EventRepository;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import com.vpssoc.domain.IpBlock;
import java.util.HashMap;
import java.util.Map;

/**
 * Playbooks: what to do when an incident opens. Each step is a fixed action type the agent
 * knows how to run safely, and the operator chooses per action type whether it runs on its
 * own (AUTO), waits for a click (APPROVAL) or never happens (OFF).
 *
 * <p>The "judgment" lives here: an IP that logged in cleanly before the burst is probably the
 * owner mistyping a password, so blocking it is only proposed, never automatic; protected
 * addresses (Tailscale, private ranges, the hPanel console) are never blocked at all.
 */
@Component
public class ResponsePlanner {

    private final ResponseService response;
    private final EventRepository events;
    private final SocProperties.Response cfg;
    private final Clock clock;

    public ResponsePlanner(ResponseService response, EventRepository events, SocProperties props, Clock clock) {
        this.clock = clock;
        this.response = response;
        this.events = events;
        this.cfg = props.response();
    }

    @EventListener
    public void onIncident(IncidentChanged change) {
        Incident inc = change.incident();
        if (cfg == null || !inc.getStatus().isActive()) {
            return;
        }
        switch (inc.getRuleId()) {
            case RuleIds.SSH_BRUTE_FORCE -> blockSource(inc, cfg.effective(cfg.blockBruteForce()), cfg.bruteForceBlockTtl(), false);
            case RuleIds.SSH_COMPROMISE -> blockSource(inc, cfg.effective(cfg.blockCompromise()), cfg.compromiseBlockTtl(), true);
            case RuleIds.SUSPICIOUS_PROCESS, RuleIds.WEB_SHELL -> killProcess(inc, change.trigger());
            case RuleIds.DISK_USAGE_HIGH -> {
                if (change.created()) {
                    response.request(inc.getHostId(), inc.getId(), Type.DISK_CLEANUP, "/", Map.of(),
                            cfg.effective(cfg.diskCleanup()),
                            "Disco acima do limite: limpar journald antigo (mantém 500 MB) e o cache do apt");
                }
            }
            case RuleIds.SERVICE_FAILED -> {
                if (change.created()) {
                    restartService(inc);
                }
            }
            default -> {
            }
        }
    }

    private void restartService(Incident inc) {
        response.request(inc.getHostId(), inc.getId(), Type.RESTART_SERVICE, inc.getDedupKey(),
                    Map.of("unit", inc.getDedupKey()), cfg.effective(cfg.restartService()),
                    "Serviço %s em falha: tentar reiniciar".formatted(inc.getDedupKey()));
    }

    private void blockSource(Incident inc, Policy policy, Duration ttl, boolean compromise) {
        String ip = inc.getSourceIp();
        if (ip == null || policy == Policy.OFF) {
            return;
        }
        Optional<IpBlock> existing = response.activeBlock(inc.getHostId(), ip);
        if (existing.isPresent()) {
            response.containIfAlreadyBlocked(inc); // e.g. the agent's local guard got there first
            boolean longEnough = existing.get().getExpiresAt().isAfter(clock.instant().plus(ttl).minus(Duration.ofHours(1)));
            if (!compromise || longEnough) {
                return;
            }
            // The attacker got in: stretch the short brute-force block to the compromise duration.
        }
        String protectedBy = response.classifier().protectedBy(ip);
        if (protectedBy != null) {
            return; // never block the owner's own paths; the explanation tells the operator why
        }
        String reason;
        if (!compromise && events.existsSuccessBefore(inc.getHostId(), ip, inc.getFirstSeen())) {
            policy = Policy.APPROVAL;
            reason = "Brute force de %s, mas esse IP já fez login com sucesso antes: pode ser você errando a senha. "
                    .formatted(ip) + "Bloqueio aguardando sua confirmação.";
        } else if (compromise) {
            reason = "Login bem-sucedido após brute force: cortar o acesso de %s (derruba sessões abertas)".formatted(ip);
        } else {
            reason = "Brute force SSH de %s: bloquear no firewall por %s".formatted(ip, human(ttl));
        }
        Map<String, Object> params = new HashMap<>();
        params.put("ip", ip);
        params.put("ttlSeconds", ttl.toSeconds());
        params.put("reason", inc.getTitle());
        response.request(inc.getHostId(), inc.getId(), Type.BLOCK_IP, ip, params, policy, reason);
    }

    private void killProcess(Incident inc, SecurityEvent trigger) {
        if (trigger == null || trigger.getType() != EventType.PROCESS_SUSPICIOUS || inc.getSeverity() != Severity.CRITICAL) {
            return; // e.g. a deleted system binary after an upgrade: restart the service, do not kill
        }
        Object pid = trigger.meta("pid");
        if (!(pid instanceof Number)) {
            return;
        }
        Map<String, Object> params = new HashMap<>();
        params.put("pid", pid);
        params.put("startTime", trigger.meta("startTime"));
        params.put("exe", trigger.meta("exe"));
        response.request(inc.getHostId(), inc.getId(), Type.KILL_PROCESS, pid + ":" + trigger.meta("startTime"), params,
                cfg.effective(cfg.killProcess()),
                "Encerrar %s (pid %s) e guardar uma cópia do binário como evidência".formatted(trigger.meta("comm"), pid));
    }

    static String human(Duration d) {
        if (d.toDays() >= 1 && d.toHours() % 24 == 0) {
            return d.toDays() + (d.toDays() == 1 ? " dia" : " dias");
        }
        if (d.toHours() >= 1) {
            return d.toHours() + " h";
        }
        return d.toMinutes() + " min";
    }
}
