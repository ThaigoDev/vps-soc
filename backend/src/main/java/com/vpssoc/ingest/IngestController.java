package com.vpssoc.ingest;

import com.vpssoc.domain.ResponseAction;
import com.vpssoc.ingest.IngestDtos.*;
import com.vpssoc.live.LiveHub;
import com.vpssoc.response.ResponseService;
import com.vpssoc.vuln.VulnerabilityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.async.DeferredResult;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** Endpoints used by the agents (authenticated with the agent token). */
@RestController
@RequestMapping("/api/v1/ingest")
public class IngestController {

    private final IngestService service;
    private final ResponseService response;
    private final VulnerabilityService vulns;
    private final LiveHub live;

    public IngestController(IngestService service, ResponseService response, VulnerabilityService vulns, LiveHub live) {
        this.live = live;
        this.vulns = vulns;
        this.service = service;
        this.response = response;
    }

    @PostMapping("/events")
    public IngestResult events(@Valid @RequestBody EventBatch batch, HttpServletRequest req) {
        return service.ingestEvents(batch.hostId(), batch.events(), req.getRemoteAddr());
    }

    @PostMapping("/heartbeat")
    public ResponseEntity<Void> heartbeat(@Valid @RequestBody Heartbeat hb, HttpServletRequest req) {
        service.heartbeat(hb, req.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    /** An app's installed packages (sent when its lockfile changes and once a day). */
    @PostMapping("/inventory")
    public ResponseEntity<Void> inventory(@Valid @RequestBody InventoryUpload u) {
        vulns.ingest(u.hostId(), u.service(), u.pm2Home(), u.lockfile(), u.hash(), u.packages());
        vulns.scanLater(u.hostId(), u.service());
        return ResponseEntity.accepted().build();
    }

    /**
     * The agent asks for approved containment actions. With {@code wait} (seconds, max 25) the
     * request stays open until an action is queued for the host or the time runs out (long
     * polling), so a block reaches the VPS the instant it is decided. Without it (older agents)
     * it answers right away.
     */
    @PostMapping("/actions/poll")
    public ActionOrders poll(@Valid @RequestBody ActionPoll req) {
        return take(req.hostId());
    }

    @PostMapping(path = "/actions/poll", params = "wait")
    public DeferredResult<ActionOrders> longPoll(@Valid @RequestBody ActionPoll req, @RequestParam int wait) {
        int seconds = Math.clamp(wait, 1, 25);
        // The container timeout is only a backstop: our own timer answers first.
        DeferredResult<ActionOrders> result = new DeferredResult<>((seconds + 15) * 1000L, () -> new ActionOrders(List.of()));
        // Register first, then look: an action queued in between still wakes us. Every path
        // that answers holds the result's lock, so actions are handed over at most once.
        Runnable deliver = () -> {
            synchronized (result) {
                if (!result.isSetOrExpired()) {
                    ActionOrders orders = take(req.hostId());
                    if (!orders.actions().isEmpty() && !result.setResult(orders)) {
                        response.requeue(orders.actions().stream().map(ActionOrder::id).toList());
                    }
                }
            }
        };
        Runnable cancel = live.waitForActions(req.hostId(), deliver);
        result.onCompletion(cancel);
        result.onTimeout(cancel);
        deliver.run();
        TIMEOUTS.schedule(() -> {
            synchronized (result) {
                if (!result.isSetOrExpired()) {
                    result.setResult(new ActionOrders(List.of()));
                }
            }
        }, seconds, TimeUnit.SECONDS);
        return result;
    }

    private ActionOrders take(String hostId) {
        return new ActionOrders(response.poll(hostId).stream()
                .map(a -> new ActionOrder(a.getId(), a.getType().name(), a.getParams()))
                .toList());
    }

    private static final ScheduledExecutorService TIMEOUTS = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "poll-timeout");
        t.setDaemon(true);
        return t;
    });

    @PostMapping("/actions/{id}/result")
    public ResponseEntity<Void> result(@PathVariable long id, @Valid @RequestBody ActionResult r) {
        ResponseAction.Status status;
        try {
            status = ResponseAction.Status.valueOf(r.status());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("status inválido: " + r.status());
        }
        response.report(id, r.hostId(), status, r.output(), r.details());
        return ResponseEntity.noContent().build();
    }
}
