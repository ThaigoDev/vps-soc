package com.vpssoc.config;

import com.vpssoc.domain.Severity;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "soc")
public record SocProperties(
        String agentToken,
        String dashboardToken,
        Retention retention,
        Detection detection,
        Telegram telegram,
        Response response) {

    public record Retention(int eventDays, int metricDays) {
    }

    public record Detection(
            int bruteForceThreshold,
            Duration bruteForceWindow,
            int sprayDistinctUsers,
            Duration sprayWindow,
            int compromiseMinFailures,
            Duration compromiseWindow,
            Duration correlationWindow,
            double diskUsagePercent,
            int offlineMissedHeartbeats,
            List<String> trustedSshSources) {

        /** Source IPs whose SSH logins are expected (e.g. the hosting provider's web console). */
        public boolean trustedSshSource(String ip) {
            return ip != null && trustedSshSources != null && trustedSshSources.stream().map(String::trim).anyMatch(ip::equals);
        }
    }

    /** AUTO runs without asking; APPROVAL waits for a click in the dashboard; OFF never proposes. */
    public enum Policy { AUTO, APPROVAL, OFF }

    public record Response(
            boolean enabled,
            Policy blockBruteForce,
            Policy blockCompromise,
            Policy killProcess,
            Policy diskCleanup,
            Policy restartService,
            Policy restartPm2,
            Duration bruteForceBlockTtl,
            Duration compromiseBlockTtl,
            double serviceMemoryPercent,
            List<String> allowlist) {

        public Policy effective(Policy p) {
            return enabled ? p : Policy.OFF;
        }
    }

    public record Telegram(String botToken, String chatId, Severity minSeverity) {

        public boolean enabled() {
            return botToken != null && !botToken.isBlank() && chatId != null && !chatId.isBlank();
        }
    }
}
