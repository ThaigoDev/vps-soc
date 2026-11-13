package com.vpssoc.live;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/** Live change stream for the dashboard (authenticated with the dashboard token). */
@RestController
@RequestMapping("/api/v1")
public class LiveController {

    private final LiveHub hub;

    public LiveController(LiveHub hub) {
        this.hub = hub;
    }

    @GetMapping(path = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        return hub.open();
    }
}
