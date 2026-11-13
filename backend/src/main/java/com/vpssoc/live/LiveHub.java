package com.vpssoc.live;

import com.vpssoc.incident.IncidentChanged;
import com.vpssoc.incident.IncidentNotification;
import com.vpssoc.response.ActionNotification;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;

/**
 * Pushes changes out the moment they are committed, instead of waiting for the next poll:
 *  - dashboards keep a Server-Sent Events stream open and get "incidents", "actions",
 *    "events" or "hosts" as soon as something changes (they then refetch that data);
 *  - agents keep an action poll open (long polling) and are woken when an action is queued.
 * Bursts are coalesced for a short moment so a batch of 500 events is one message.
 */
@Component
public class LiveHub {

    private static final Logger log = LoggerFactory.getLogger(LiveHub.class);
    private static final long COALESCE_MS = 150;
    static final Duration STREAM_TIMEOUT = Duration.ofMinutes(30);

    private final List<SseEmitter> streams = new CopyOnWriteArrayList<>();
    private final Map<String, List<Runnable>> waitingAgents = new ConcurrentHashMap<>();
    private final Set<String> pendingTopics = ConcurrentHashMap.newKeySet();
    private final java.util.concurrent.atomic.AtomicBoolean flushScheduled = new java.util.concurrent.atomic.AtomicBoolean();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "live-hub");
        t.setDaemon(true);
        return t;
    });
    private final ExecutorService wakers = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "live-wake");
        t.setDaemon(true);
        return t;
    });

    // ---- dashboards (SSE) ------------------------------------------------------------------

    public SseEmitter open() {
        SseEmitter emitter = new SseEmitter(STREAM_TIMEOUT.toMillis());
        streams.add(emitter);
        Runnable remove = () -> streams.remove(emitter);
        emitter.onCompletion(remove);
        emitter.onTimeout(remove);
        emitter.onError(e -> remove.run());
        try {
            emitter.send(SseEmitter.event().name("hello").data("ok").reconnectTime(2000));
        } catch (IOException e) {
            remove.run();
        }
        return emitter;
    }

    public int streams() {
        return streams.size();
    }

    /** Queues a topic; all topics raised within a few milliseconds go out together. */
    public void publish(String topic) {
        pendingTopics.add(topic);
        if (flushScheduled.compareAndSet(false, true)) {
            timer.schedule(this::flush, COALESCE_MS, TimeUnit.MILLISECONDS);
        }
    }

    private void flush() {
        flushScheduled.set(false);
        List<String> topics = List.copyOf(pendingTopics);
        pendingTopics.removeAll(topics);
        for (String topic : topics) {
            send(SseEmitter.event().name("change").data(topic));
        }
    }

    /** Keeps proxies from closing idle streams. */
    @Scheduled(fixedDelay = 20_000, initialDelay = 20_000)
    public void keepAlive() {
        send(SseEmitter.event().comment("ping"));
    }

    private void send(SseEmitter.SseEventBuilder event) {
        for (SseEmitter e : streams) {
            try {
                e.send(event);
            } catch (IOException | IllegalStateException ex) {
                streams.remove(e);
                e.completeWithError(ex);
            }
        }
    }

    // ---- agents (long polling) -----------------------------------------------------------

    /** Registers a callback to run (on another thread) when an action may be waiting for this host. */
    public Runnable waitForActions(String hostId, Runnable wake) {
        List<Runnable> list = waitingAgents.computeIfAbsent(hostId, k -> new CopyOnWriteArrayList<>());
        list.add(wake);
        return () -> list.remove(wake);
    }

    public void wakeAgent(String hostId) {
        List<Runnable> list = hostId == null ? waitingAgents.values().stream().flatMap(List::stream).toList()
                : waitingAgents.getOrDefault(hostId, List.of());
        for (Runnable r : List.copyOf(list)) {
            wakers.submit(() -> {
                try {
                    r.run();
                } catch (RuntimeException ex) {
                    log.warn("waking agent {} failed: {}", hostId, ex.toString());
                }
            });
        }
    }

    // ---- what triggers a push --------------------------------------------------------------

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void on(IncidentNotification n) {
        publish("incidents");
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void on(IncidentChanged c) {
        publish("incidents");
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void on(ActionNotification n) {
        publish("actions");
        if (n.kind() == ActionNotification.Kind.QUEUED) {
            wakeAgent(null);
        }
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void on(LiveUpdate u) {
        publish(u.topic());
        if ("actions".equals(u.topic())) {
            wakeAgent(u.hostId());
        }
    }

    @PreDestroy
    void stop() {
        timer.shutdownNow();
        wakers.shutdownNow();
        streams.forEach(SseEmitter::complete);
    }
}
