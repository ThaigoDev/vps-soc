package com.vpssoc.detection.rules;

import com.vpssoc.detection.Detection;
import com.vpssoc.detection.DetectionRule;
import com.vpssoc.domain.EventType;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import com.vpssoc.repository.EventRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * PM2 apps: a crash (status errored) or a stop raises SERVICE_DOWN; restarts piling up
 * inside a short window raise SERVICE_CRASH_LOOP (pm2 keeps such an app "online" between
 * crashes, so status alone hides it). Recovery is detected on the heartbeat
 * ({@link com.vpssoc.service.ServiceEvaluator}).
 */
@Component
public class ServiceRules implements DetectionRule {

    static final Duration LOOP_WINDOW = Duration.ofMinutes(10);
    static final int LOOP_RESTARTS = 3;

    private final EventRepository events;

    public ServiceRules(EventRepository events) {
        this.events = events;
    }

    @Override
    public Set<EventType> triggers() {
        return Set.of(EventType.SERVICE_STATUS_CHANGED, EventType.SERVICE_RESTARTED);
    }

    @Override
    public List<Detection> evaluate(SecurityEvent e) {
        Object name = e.meta("service");
        if (name == null) {
            return List.of();
        }
        String svc = name.toString();
        String host = e.getHostId();

        if (e.getType() == EventType.SERVICE_STATUS_CHANGED) {
            String to = String.valueOf(e.meta("to"));
            if ("errored".equals(to) || "stopped".equals(to)) {
                return List.of(down(host, svc, to, e.meta("from")));
            }
            return List.of(Detection.attachIfActive(host, RuleIds.SERVICE_DOWN, svc).build());
        }

        Instant to = e.getOccurredAt();
        Instant from = to.minus(LOOP_WINDOW);
        long restarts = events.sumServiceRestarts(host, svc, from.minusMillis(1));
        if (restarts < LOOP_RESTARTS) {
            return List.of(
                    Detection.attachIfActive(host, RuleIds.SERVICE_CRASH_LOOP, svc).build(),
                    Detection.attachIfActive(host, RuleIds.SERVICE_DOWN, svc).build());
        }
        return List.of(
                Detection.raise(host, RuleIds.SERVICE_CRASH_LOOP, svc)
                        .title("App PM2 em crash loop: " + svc)
                        .description("%s reiniciou %d vezes nos últimos %d minutos (total %s desde que foi iniciado no PM2)."
                                .formatted(svc, restarts, LOOP_WINDOW.toMinutes(), e.meta("restarts")))
                        .severity(Severity.HIGH)
                        .risk((int) Math.min(80, 50 + restarts))
                        .service(svc)
                        .username(e.getUsername())
                        .related(() -> events.serviceEventIds(host, svc, from))
                        .build(),
                Detection.attachIfActive(host, RuleIds.SERVICE_DOWN, svc).build());
    }

    public static Detection down(String host, String svc, String status, Object from) {
        boolean crashed = "errored".equals(status);
        return Detection.raise(host, RuleIds.SERVICE_DOWN, svc)
                .title(crashed ? "App PM2 caiu: " + svc : "App PM2 parado: " + svc)
                .description(crashed
                        ? "%s está com status errored no PM2: o processo terminou com erro e o PM2 desistiu de reiniciar.".formatted(svc)
                        : "%s está com status stopped no PM2%s.".formatted(svc, from == null ? "" : " (antes: " + from + ")"))
                .severity(crashed ? Severity.HIGH : Severity.MEDIUM)
                .risk(crashed ? 65 : 35)
                .service(svc)
                .build();
    }
}
