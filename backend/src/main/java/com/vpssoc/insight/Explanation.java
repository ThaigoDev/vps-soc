package com.vpssoc.insight;

import java.time.Instant;
import java.util.List;

/** A plain-language write-up of an incident for the operator (and the Telegram alert). */
public record Explanation(
        String summary,
        String impact,
        List<String> riskFactors,
        List<Fact> evidence,
        String response,
        List<Step> recommendations,
        String falsePositive) {

    public record Fact(String label, String value) {
    }

    /** A next step; command is optional and meant to be copied into the VPS terminal. */
    public record Step(String title, String detail, String command) {
    }

    public record UserCount(String username, long attempts) {
    }

    public record IpProfile(String ip, String kind, String kindLabel, String protectedBy, boolean trustedSource,
                            Instant firstSeen, Instant lastSeen, long failures, long successes, long usernamesTried,
                            List<UserCount> topUsernames, long incidents, Instant blockedUntil, String blockOrigin,
                            boolean everLoggedIn) {
    }
}
