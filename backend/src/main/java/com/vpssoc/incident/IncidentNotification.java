package com.vpssoc.incident;

/** Published inside the transaction; notifiers react after it commits. */
public record IncidentNotification(long incidentId, Kind kind) {

    public enum Kind { CREATED, ESCALATED }
}
