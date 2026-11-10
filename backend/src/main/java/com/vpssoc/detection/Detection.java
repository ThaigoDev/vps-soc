package com.vpssoc.detection;

import com.vpssoc.domain.Severity;

import java.util.List;
import java.util.function.Supplier;

/**
 * What a rule concluded about an event. {@link Mode#RAISE} opens an incident (or adds the
 * evidence to the active one with the same rule + key); {@link Mode#ATTACH_IF_ACTIVE} only adds
 * evidence when such an incident is already active, which is how follow-up activity gets
 * correlated into an existing incident. A null dedupKey with ATTACH_IF_ACTIVE targets every
 * active incident of the rule on that host.
 */
public record Detection(
        Mode mode,
        String hostId,
        String ruleId,
        String dedupKey,
        String title,
        String description,
        Severity severity,
        int riskScore,
        List<String> techniques,
        String sourceIp,
        String username,
        Supplier<List<Long>> relatedEventIds,
        String service) {

    public enum Mode { RAISE, ATTACH_IF_ACTIVE }

    public Detection {
        // Keys can embed agent-reported paths; lookup and insert must see the same VARCHAR(255) value.
        if (dedupKey != null && dedupKey.length() > 255) {
            dedupKey = dedupKey.substring(0, 255);
        }
    }

    public static Builder raise(String hostId, String ruleId, String dedupKey) {
        return new Builder(Mode.RAISE, hostId, ruleId, dedupKey);
    }

    public static Builder attachIfActive(String hostId, String ruleId, String dedupKey) {
        return new Builder(Mode.ATTACH_IF_ACTIVE, hostId, ruleId, dedupKey);
    }

    public static final class Builder {
        private final Mode mode;
        private final String hostId;
        private final String ruleId;
        private final String dedupKey;
        private String title;
        private String description;
        private Severity severity = Severity.LOW;
        private int riskScore;
        private List<String> techniques = List.of();
        private String sourceIp;
        private String username;
        private Supplier<List<Long>> related = List::of;
        private String service;

        private Builder(Mode mode, String hostId, String ruleId, String dedupKey) {
            this.mode = mode;
            this.hostId = hostId;
            this.ruleId = ruleId;
            this.dedupKey = dedupKey;
        }

        public Builder title(String v) { title = v; return this; }
        public Builder description(String v) { description = v; return this; }
        public Builder severity(Severity v) { severity = v; return this; }
        public Builder risk(int v) { riskScore = v; return this; }
        public Builder techniques(String... ids) { techniques = List.of(ids); return this; }
        public Builder sourceIp(String v) { sourceIp = v; return this; }
        public Builder username(String v) { username = v; return this; }
        /** Earlier events to link as evidence when the incident is first created. */
        public Builder related(Supplier<List<Long>> v) { related = v; return this; }
        /** The PM2 app this incident is about (its own failure, or a port/process it owns). */
        public Builder service(String v) { service = v; return this; }

        public Detection build() {
            return new Detection(mode, hostId, ruleId, dedupKey, title, description, severity, riskScore,
                    techniques, sourceIp, username, related, service);
        }
    }
}
