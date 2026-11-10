package com.vpssoc.incident;

import com.vpssoc.detection.Detection;
import com.vpssoc.domain.Incident;
import com.vpssoc.domain.IncidentStatus;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import com.vpssoc.repository.IncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class IncidentService {

    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    private final IncidentRepository incidents;
    private final ApplicationEventPublisher publisher;
    private final Clock clock;

    public IncidentService(IncidentRepository incidents, ApplicationEventPublisher publisher, Clock clock) {
        this.incidents = incidents;
        this.publisher = publisher;
        this.clock = clock;
    }

    /**
     * Applies a rule's detection. {@code trigger} is the event that fired it, or null for
     * host-state detections (agent offline, disk full) that have no single event.
     */
    @Transactional
    public void apply(Detection d, SecurityEvent trigger) {
        Instant now = clock.instant();
        Instant seenAt = trigger != null ? trigger.getOccurredAt() : now;

        if (d.mode() == Detection.Mode.ATTACH_IF_ACTIVE) {
            List<Incident> targets = d.dedupKey() == null
                    ? incidents.findByHostIdAndRuleIdAndStatusIn(d.hostId(), d.ruleId(), IncidentStatus.ACTIVE)
                    : findActive(d.hostId(), d.ruleId(), d.dedupKey()).stream().toList();
            for (Incident inc : targets) {
                inc.addTechniques(d.techniques());
                if (d.riskScore() > inc.getRiskScore()) {
                    inc.setRiskScore(d.riskScore());
                }
                link(inc, trigger, seenAt, now);
            }
            return;
        }

        Optional<Incident> active = findActive(d.hostId(), d.ruleId(), d.dedupKey());
        if (active.isPresent()) {
            Incident inc = active.get();
            boolean escalated = d.severity().compareTo(inc.getSeverity()) > 0;
            inc.setTitle(d.title());
            inc.setDescription(d.description());
            if (inc.getService() == null && d.service() != null) {
                inc.setService(d.service());
            }
            inc.setSeverity(Severity.max(inc.getSeverity(), d.severity()));
            inc.setRiskScore(Math.max(inc.getRiskScore(), d.riskScore()));
            inc.addTechniques(d.techniques());
            link(inc, trigger, seenAt, now);
            publisher.publishEvent(new IncidentChanged(inc, trigger, false));
            if (escalated) {
                publisher.publishEvent(new IncidentNotification(inc.getId(), IncidentNotification.Kind.ESCALATED));
            }
            return;
        }

        Incident inc = new Incident(d.hostId(), d.ruleId(), d.dedupKey(), seenAt, now);
        inc.setTitle(d.title());
        inc.setDescription(d.description());
        inc.setSeverity(d.severity());
        inc.setRiskScore(d.riskScore());
        inc.setSourceIp(d.sourceIp());
        inc.setUsername(d.username());
        inc.setService(d.service());
        inc.addTechniques(d.techniques());
        incidents.save(inc);

        int linked = 0;
        for (Long eventId : d.relatedEventIds().get()) {
            linked += incidents.link(inc.getId(), eventId);
        }
        if (trigger != null) {
            linked += incidents.link(inc.getId(), trigger.getId());
        }
        inc.recordEvidence(seenAt, linked, now);
        if (linked > 1) {
            incidents.earliestEvidence(inc.getId()).ifPresent(inc::backdateFirstSeen);
        }
        log.info("Incident #{} {} [{}] {}", inc.getId(), d.ruleId(), d.severity(), d.title());
        publisher.publishEvent(new IncidentChanged(inc, trigger, true));
        publisher.publishEvent(new IncidentNotification(inc.getId(), IncidentNotification.Kind.CREATED));
    }

    /** Closes the active incident for a rule + key, e.g. when the agent comes back online. */
    @Transactional
    public void resolveActive(String hostId, String ruleId, String dedupKey, String note) {
        findActive(hostId, ruleId, dedupKey).ifPresent(inc -> {
            inc.changeStatus(IncidentStatus.RESOLVED, note, clock.instant());
            log.info("Incident #{} {} auto-resolved: {}", inc.getId(), ruleId, note);
        });
    }

    @Transactional
    public Incident changeStatus(long id, IncidentStatus status, String note) {
        Incident inc = incidents.findById(id).orElseThrow(() -> new IncidentNotFoundException(id));
        if (status.isActive() && !inc.getStatus().isActive()) {
            // Re-opening would collide with a newer active incident on the same rule + key.
            Optional<Incident> other = findActive(inc.getHostId(), inc.getRuleId(), inc.getDedupKey());
            if (other.isPresent()) {
                throw new IllegalStateException("incident #" + other.get().getId() + " is already active for the same rule and key");
            }
        }
        inc.changeStatus(status, note, clock.instant());
        return inc;
    }

    private Optional<Incident> findActive(String hostId, String ruleId, String dedupKey) {
        return incidents.findFirstByHostIdAndRuleIdAndDedupKeyAndStatusIn(hostId, ruleId, dedupKey, IncidentStatus.ACTIVE);
    }

    private void link(Incident inc, SecurityEvent trigger, Instant seenAt, Instant now) {
        int added = trigger != null ? incidents.link(inc.getId(), trigger.getId()) : 0;
        inc.recordEvidence(seenAt, added, now);
    }
}
