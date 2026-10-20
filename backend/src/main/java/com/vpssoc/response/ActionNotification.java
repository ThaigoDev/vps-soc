package com.vpssoc.response;

/** Published inside the transaction; notifiers react after it commits. */
public record ActionNotification(long actionId, Kind kind) {

    public enum Kind { QUEUED, NEEDS_APPROVAL, COMPLETED }
}
