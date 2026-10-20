package com.vpssoc.incident;

import com.vpssoc.domain.Incident;
import com.vpssoc.domain.SecurityEvent;

/**
 * Published synchronously, inside the transaction, whenever a rule raises a new incident
 * or adds evidence to an active one. Playbooks listen to it to plan a response.
 * {@code trigger} is null for host-state incidents (disk, posture, agent offline).
 */
public record IncidentChanged(Incident incident, SecurityEvent trigger, boolean created) {
}
