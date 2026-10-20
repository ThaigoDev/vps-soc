package com.vpssoc.response;

import com.vpssoc.config.SocProperties;
import com.vpssoc.detection.rules.RuleIds;
import com.vpssoc.domain.*;
import com.vpssoc.domain.ResponseAction.Mode;
import com.vpssoc.domain.ResponseAction.Origin;
import com.vpssoc.domain.ResponseAction.Status;
import com.vpssoc.domain.ResponseAction.Type;
import com.vpssoc.repository.IncidentRepository;
import com.vpssoc.repository.IpBlockRepository;
import com.vpssoc.repository.ResponseActionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;

/**
 * The action queue between the SOC and the agents: creates actions (automatic or waiting
 * for approval), hands them to the agent when it polls, and applies the result
 * (records the IP block, marks the incident as contained, closes what is fully handled).
 */
@Service
public class ResponseService {

    private static final Logger log = LoggerFactory.getLogger(ResponseService.class);
    private static final EnumSet<Status> OPEN = EnumSet.of(Status.PROPOSED, Status.PENDING, Status.SENT);
    private static final Duration PENDING_EXPIRY = Duration.ofHours(24);
    private static final Duration SENT_TIMEOUT = Duration.ofMinutes(5);
    static final DateTimeFormatter LOCAL_TIME = DateTimeFormatter.ofPattern("dd/MM HH:mm").withZone(ZoneId.of("America/Sao_Paulo"));

    private final ResponseActionRepository actions;
    private final IpBlockRepository blocks;
    private final IncidentRepository incidents;
    private final ApplicationEventPublisher publisher;
    private final IpClassifier classifier;
    private final Clock clock;

    public ResponseService(ResponseActionRepository actions, IpBlockRepository blocks, IncidentRepository incidents,
                           ApplicationEventPublisher publisher, SocProperties props, Clock clock) {
        this.actions = actions;
        this.blocks = blocks;
        this.incidents = incidents;
        this.publisher = publisher;
        List<String> allow = new ArrayList<>();
        if (props.response() != null && props.response().allowlist() != null) {
            allow.addAll(props.response().allowlist());
        }
        if (props.detection().trustedSshSources() != null) {
            allow.addAll(props.detection().trustedSshSources());
        }
        this.classifier = new IpClassifier(allow);
        this.clock = clock;
    }

    public IpClassifier classifier() {
        return classifier;
    }

    /**
     * Creates an action unless an equivalent one is already open. Returns the action, or
     * empty when it was skipped as a duplicate.
     */
    @Transactional
    public Optional<ResponseAction> request(String hostId, Long incidentId, Type type, String target,
                                            Map<String, Object> params, SocProperties.Policy policy, String reason) {
        if (policy == SocProperties.Policy.OFF) {
            return Optional.empty();
        }
        List<ResponseAction> open = actions.findByHostIdAndTypeAndTargetAndStatusIn(hostId, type, target, OPEN);
        if (!open.isEmpty()) {
            // Same action already queued: let the more serious request win (longer block, no approval).
            for (ResponseAction ex : open) {
                if (ex.getStatus() == Status.SENT) {
                    continue;
                }
                if (type == Type.BLOCK_IP && ttl(params) > ttl(ex.getParams())) {
                    Map<String, Object> p = new HashMap<>(ex.getParams());
                    p.put("ttlSeconds", ttl(params));
                    ex.setParams(p);
                    ex.setReason(reason);
                }
                if (policy == SocProperties.Policy.AUTO && ex.getStatus() == Status.PROPOSED) {
                    ex.escalate(reason, clock.instant());
                }
            }
            return Optional.empty();
        }
        if (policy == SocProperties.Policy.APPROVAL && actions.existsByHostIdAndTypeAndTargetAndStatusAndCompletedAtAfter(
                hostId, type, target, Status.DISMISSED, clock.instant().minus(Duration.ofHours(24)))) {
            return Optional.empty(); // the operator already said no to this one today
        }
        Status status = policy == SocProperties.Policy.AUTO ? Status.PENDING : Status.PROPOSED;
        Mode mode = policy == SocProperties.Policy.AUTO ? Mode.AUTO : Mode.MANUAL;
        ResponseAction a = actions.save(new ResponseAction(hostId, incidentId, type, target, new HashMap<>(params),
                status, mode, Origin.SOC, reason, clock.instant()));
        log.info("Response action #{} {} {} on {} [{}]: {}", a.getId(), type, target, hostId, status, reason);
        publisher.publishEvent(new ActionNotification(a.getId(), status == Status.PROPOSED
                ? ActionNotification.Kind.NEEDS_APPROVAL : ActionNotification.Kind.QUEUED));
        return Optional.of(a);
    }

    /** Manual block from the dashboard. */
    @Transactional
    public ResponseAction blockManually(String hostId, String ip, Duration ttl, Long incidentId, String reason) {
        String why = classifier.protectedBy(ip);
        if (why != null) {
            throw new IllegalArgumentException("%s está protegido (%s) e não pode ser bloqueado".formatted(ip, why));
        }
        long secs = Math.clamp(ttl.toSeconds(), 60, Duration.ofDays(30).toSeconds());
        return request(hostId, incidentId, Type.BLOCK_IP, ip,
                Map.of("ip", ip, "ttlSeconds", secs, "reason", reason == null ? "bloqueio manual" : reason),
                SocProperties.Policy.AUTO, reason == null ? "Bloqueio manual pelo painel" : reason)
                .orElseThrow(() -> new IllegalStateException("já existe um bloqueio em andamento para " + ip));
    }

    @Transactional
    public ResponseAction unblock(long blockId) {
        IpBlock b = blocks.findById(blockId).orElseThrow(() -> new IllegalArgumentException("bloqueio #" + blockId + " não existe"));
        if (!b.activeAt(clock.instant())) {
            throw new IllegalStateException("o bloqueio de " + b.getIp() + " já não está ativo");
        }
        return request(b.getHostId(), b.getIncidentId(), Type.UNBLOCK_IP, b.getIp(), Map.of("ip", b.getIp()),
                SocProperties.Policy.AUTO, "Desbloqueio manual pelo painel")
                .orElseThrow(() -> new IllegalStateException("já existe um desbloqueio em andamento para " + b.getIp()));
    }

    @Transactional
    public ResponseAction approve(long id) {
        ResponseAction a = find(id);
        if (a.getStatus() != Status.PROPOSED) {
            throw new IllegalStateException("ação #" + id + " não está aguardando aprovação (" + a.getStatus() + ")");
        }
        a.approve(clock.instant());
        return a;
    }

    @Transactional
    public ResponseAction dismiss(long id) {
        ResponseAction a = find(id);
        if (a.getStatus() != Status.PROPOSED && a.getStatus() != Status.PENDING) {
            throw new IllegalStateException("ação #" + id + " não pode mais ser descartada (" + a.getStatus() + ")");
        }
        a.dismiss(clock.instant());
        return a;
    }

    /** Called by the agent: hands over everything approved for that host. */
    @Transactional
    public List<ResponseAction> poll(String hostId) {
        List<ResponseAction> pending = actions.findByHostIdAndStatusOrderByIdAsc(hostId, Status.PENDING);
        Instant now = clock.instant();
        pending.forEach(a -> a.dispatch(now));
        return pending;
    }

    /** Called by the agent with the outcome of an action. */
    @Transactional
    public ResponseAction report(long id, String hostId, Status status, String output, Map<String, Object> details) {
        ResponseAction a = find(id);
        if (!a.getHostId().equals(hostId)) {
            throw new IllegalArgumentException("ação #" + id + " não pertence ao host " + hostId);
        }
        if (!a.getStatus().open()) {
            return a; // duplicate report after a retry
        }
        if (status != Status.SUCCEEDED && status != Status.FAILED && status != Status.REJECTED) {
            throw new IllegalArgumentException("status de resultado inválido: " + status);
        }
        Instant now = clock.instant();
        a.complete(status, output, details, now);
        log.info("Response action #{} {} {} -> {}: {}", a.getId(), a.getType(), a.getTarget(), status, output);
        if (status == Status.SUCCEEDED) {
            applyEffects(a, details, now);
        }
        publisher.publishEvent(new ActionNotification(a.getId(), ActionNotification.Kind.COMPLETED));
        return a;
    }

    /** The agent blocked an IP on its own (local guard, SOC may have been offline). */
    @Transactional
    public void recordAgentAction(SecurityEvent e) {
        Object action = e.meta("action");
        String ip = e.getSourceIp();
        if (!"BLOCK_IP".equals(String.valueOf(action)) || ip == null) {
            return;
        }
        Status status = "SUCCEEDED".equals(String.valueOf(e.meta("status"))) ? Status.SUCCEEDED : Status.FAILED;
        Instant now = clock.instant();
        Long incidentId = activeIncidentFor(e.getHostId(), RuleIds.SSH_BRUTE_FORCE, ip).map(Incident::getId).orElse(null);
        ResponseAction a = new ResponseAction(e.getHostId(), incidentId, Type.BLOCK_IP, ip,
                new HashMap<>(Map.of("ip", ip, "ttlSeconds", e.meta("ttlSeconds") == null ? 0 : e.meta("ttlSeconds"))),
                Status.SENT, Mode.AUTO, Origin.AGENT, "Guarda local do agente: " + e.meta("reason"), e.getOccurredAt());
        actions.save(a);
        Map<String, Object> details = new HashMap<>();
        if (e.meta("until") != null) {
            details.put("until", e.meta("until"));
        }
        a.complete(status, e.getMessage(), details, now);
        if (status == Status.SUCCEEDED) {
            applyEffects(a, details, now);
        }
        publisher.publishEvent(new ActionNotification(a.getId(), ActionNotification.Kind.COMPLETED));
    }

    private void applyEffects(ResponseAction a, Map<String, Object> details, Instant now) {
        switch (a.getType()) {
            case BLOCK_IP -> {
                Instant until = until(details, a, now);
                IpBlock block = blocks.active(a.getHostId(), a.getTarget(), now).orElse(null);
                if (block == null) {
                    blocks.save(new IpBlock(a.getHostId(), a.getTarget(), a.getReason(), a.getOrigin(), a.getId(),
                            a.getIncidentId(), now, until));
                } else {
                    block.extendTo(until);
                }
                containIpIncidents(a.getHostId(), a.getTarget(), until, a.getOrigin(), now);
                // A block queued by the SOC is redundant once the IP is already blocked (e.g. by the agent's guard).
                for (ResponseAction other : actions.findByHostIdAndTypeAndTargetAndStatusIn(a.getHostId(), Type.BLOCK_IP, a.getTarget(),
                        EnumSet.of(Status.PROPOSED, Status.PENDING))) {
                    if (!other.getId().equals(a.getId())) {
                        other.complete(Status.DISMISSED, "Desnecessário: o IP já foi bloqueado (ação #" + a.getId() + ")", null, now);
                    }
                }
            }
            case UNBLOCK_IP -> blocks.findActive(a.getHostId(), a.getTarget(), now).forEach(b -> b.remove(now));
            case KILL_PROCESS -> incident(a).ifPresent(inc -> inc.contain(
                    "Processo encerrado pelo agente em %s. %s".formatted(LOCAL_TIME.format(now), Objects.toString(a.getResult(), "")), now));
            case DISK_CLEANUP -> incident(a).ifPresent(inc -> inc.contain(
                    "Limpeza automática de disco: " + a.getResult(), now));
            case RESTART_SERVICE -> incident(a).ifPresent(inc -> inc.contain(
                    "Serviço reiniciado: " + a.getResult(), now));
        }
    }

    /**
     * After an IP is blocked: every active incident from that IP on the host is contained.
     * A plain brute force (no login succeeded) is fully handled by the block, so it is
     * closed; a compromise stays open because someone still has to clean the account.
     */
    void containIpIncidents(String hostId, String ip, Instant until, Origin origin, Instant now) {
        String who = origin == Origin.AGENT ? "pelo agente (guarda local)" : "pelo SOC";
        String note = "IP %s bloqueado no firewall %s até %s.".formatted(ip, who, LOCAL_TIME.format(until));
        for (Incident inc : incidents.findByHostIdAndSourceIpAndStatusIn(hostId, ip, IncidentStatus.ACTIVE)) {
            inc.contain(note, now);
            if (RuleIds.SSH_BRUTE_FORCE.equals(inc.getRuleId())) {
                inc.changeStatus(IncidentStatus.RESOLVED, "Contido automaticamente: " + note
                        + " Nenhum login do atacante teve sucesso.", now);
            }
        }
    }

    /** An incident opened after its IP was already blocked (e.g. by the agent's guard). */
    public boolean containIfAlreadyBlocked(Incident inc) {
        if (inc.getSourceIp() == null) {
            return false;
        }
        Instant now = clock.instant();
        Optional<IpBlock> b = blocks.active(inc.getHostId(), inc.getSourceIp(), now);
        b.ifPresent(block -> containIpIncidents(inc.getHostId(), inc.getSourceIp(), block.getExpiresAt(), block.getOrigin(), now));
        return b.isPresent();
    }

    public Optional<IpBlock> activeBlock(String hostId, String ip) {
        return blocks.active(hostId, ip, clock.instant());
    }

    public List<IpBlock> activeBlocks() {
        return blocks.findAllActive(clock.instant());
    }

    /** Housekeeping: approvals nobody acted on expire; dispatched actions with no answer fail. */
    @Scheduled(fixedDelay = 60_000, initialDelay = 60_000)
    @Transactional
    public void expireStale() {
        Instant now = clock.instant();
        for (ResponseAction a : actions.findByStatusAndCreatedAtBefore(Status.PROPOSED, now.minus(PENDING_EXPIRY))) {
            a.complete(Status.EXPIRED, "Expirou sem aprovação", null, now);
        }
        for (ResponseAction a : actions.findByStatusAndCreatedAtBefore(Status.PENDING, now.minus(PENDING_EXPIRY))) {
            a.complete(Status.EXPIRED, "O agente não buscou a ação em 24h (offline?)", null, now);
        }
        for (ResponseAction a : actions.findByStatusAndDispatchedAtBefore(Status.SENT, now.minus(SENT_TIMEOUT))) {
            a.complete(Status.FAILED, "O agente recebeu a ação mas não informou o resultado em 5 min", null, now);
        }
    }

    private Optional<Incident> incident(ResponseAction a) {
        return a.getIncidentId() == null ? Optional.empty() : incidents.findById(a.getIncidentId());
    }

    private Optional<Incident> activeIncidentFor(String hostId, String ruleId, String key) {
        return incidents.findFirstByHostIdAndRuleIdAndDedupKeyAndStatusIn(hostId, ruleId, key, IncidentStatus.ACTIVE);
    }

    private ResponseAction find(long id) {
        return actions.findById(id).orElseThrow(() -> new IllegalArgumentException("ação #" + id + " não existe"));
    }

    private static long ttl(Map<String, Object> params) {
        return params != null && params.get("ttlSeconds") instanceof Number n ? n.longValue() : 0;
    }

    private static Instant until(Map<String, Object> details, ResponseAction a, Instant now) {
        if (details != null && details.get("until") != null) {
            try {
                return OffsetDateTime.parse(details.get("until").toString()).toInstant();
            } catch (DateTimeParseException ignored) {
                // fall back to the requested TTL
            }
        }
        Object ttl = a.getParams().get("ttlSeconds");
        long secs = ttl instanceof Number n ? n.longValue() : 86_400;
        return now.plusSeconds(secs > 0 ? secs : 86_400);
    }
}
