package com.vpssoc.jobs;

import com.vpssoc.config.SocProperties;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.HostMetricRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;

/** Daily cleanup; events that are evidence of an incident are kept. */
@Component
public class RetentionJob {

    private static final Logger log = LoggerFactory.getLogger(RetentionJob.class);

    private final EventRepository events;
    private final HostMetricRepository metrics;
    private final com.vpssoc.repository.ServiceSampleRepository serviceSamples;
    private final SocProperties.Retention cfg;
    private final Clock clock;

    public RetentionJob(EventRepository events, HostMetricRepository metrics, SocProperties props, Clock clock,
                        com.vpssoc.repository.ServiceSampleRepository serviceSamples) {
        this.serviceSamples = serviceSamples;
        this.events = events;
        this.metrics = metrics;
        this.cfg = props.retention();
        this.clock = clock;
    }

    @Scheduled(cron = "0 30 3 * * *")
    @Transactional
    public void purge() {
        int e = events.deleteOlderThan(clock.instant().minus(Duration.ofDays(cfg.eventDays())));
        int m = metrics.deleteOlderThan(clock.instant().minus(Duration.ofDays(cfg.metricDays())));
        m += serviceSamples.deleteOlderThan(clock.instant().minus(Duration.ofDays(cfg.metricDays())));
        log.info("Retention: removed {} events and {} metric samples", e, m);
    }
}
