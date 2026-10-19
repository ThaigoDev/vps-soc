package com.vpssoc.domain;

import java.util.EnumSet;
import java.util.Set;

public enum IncidentStatus {
    OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE;

    /** Statuses in which new evidence is still attached to the incident. */
    public static final Set<IncidentStatus> ACTIVE = EnumSet.of(OPEN, ACKNOWLEDGED);

    public boolean isActive() {
        return ACTIVE.contains(this);
    }
}
