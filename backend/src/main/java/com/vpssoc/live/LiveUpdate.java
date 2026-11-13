package com.vpssoc.live;

/**
 * Something the dashboard (and maybe an agent) should hear about right away.
 * Published inside or outside a transaction; delivered after commit.
 * {@code topic}: incidents, actions, events or hosts.
 */
public record LiveUpdate(String topic, String hostId) {
}
