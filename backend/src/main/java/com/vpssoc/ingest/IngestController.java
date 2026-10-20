package com.vpssoc.ingest;

import com.vpssoc.domain.ResponseAction;
import com.vpssoc.ingest.IngestDtos.*;
import com.vpssoc.response.ResponseService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** Endpoints used by the agents (authenticated with the agent token). */
@RestController
@RequestMapping("/api/v1/ingest")
public class IngestController {

    private final IngestService service;
    private final ResponseService response;

    public IngestController(IngestService service, ResponseService response) {
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

    /** The agent asks for approved containment actions every few seconds. */
    @PostMapping("/actions/poll")
    public ActionOrders poll(@Valid @RequestBody ActionPoll req) {
        return new ActionOrders(response.poll(req.hostId()).stream()
                .map(a -> new ActionOrder(a.getId(), a.getType().name(), a.getParams()))
                .toList());
    }

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
