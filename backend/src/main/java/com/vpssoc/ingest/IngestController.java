package com.vpssoc.ingest;

import com.vpssoc.ingest.IngestDtos.EventBatch;
import com.vpssoc.ingest.IngestDtos.Heartbeat;
import com.vpssoc.ingest.IngestDtos.IngestResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** Endpoints used by the agents (authenticated with the agent token). */
@RestController
@RequestMapping("/api/v1/ingest")
public class IngestController {

    private final IngestService service;

    public IngestController(IngestService service) {
        this.service = service;
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
}
