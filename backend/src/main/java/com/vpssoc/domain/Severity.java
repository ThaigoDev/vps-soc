package com.vpssoc.domain;

public enum Severity {
    INFO(0), LOW(1), MEDIUM(5), HIGH(20), CRITICAL(40);

    /** Points an open incident of this severity takes off the security score. */
    private final int scorePenalty;

    Severity(int scorePenalty) {
        this.scorePenalty = scorePenalty;
    }

    public int scorePenalty() {
        return scorePenalty;
    }

    public boolean atLeast(Severity other) {
        return compareTo(other) >= 0;
    }

    public static Severity max(Severity a, Severity b) {
        return a.compareTo(b) >= 0 ? a : b;
    }
}
