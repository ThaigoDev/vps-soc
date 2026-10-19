package com.vpssoc.detection;

import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.incident.IncidentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    private final List<DetectionRule> rules;
    private final IncidentService incidents;

    public DetectionEngine(List<DetectionRule> rules, IncidentService incidents) {
        this.rules = rules;
        this.incidents = incidents;
        log.info("Detection engine loaded {} rules", rules.size());
    }

    /** Runs every rule interested in the event; must be called inside the ingest transaction. */
    public void process(SecurityEvent event) {
        for (DetectionRule rule : rules) {
            if (rule.triggers().contains(event.getType())) {
                for (Detection detection : rule.evaluate(event)) {
                    incidents.apply(detection, event);
                }
            }
        }
    }
}
