package com.vpssoc.detection;

import com.vpssoc.domain.EventType;
import com.vpssoc.domain.SecurityEvent;

import java.util.List;
import java.util.Set;

public interface DetectionRule {

    /** Event types this rule looks at. */
    Set<EventType> triggers();

    List<Detection> evaluate(SecurityEvent event);
}
