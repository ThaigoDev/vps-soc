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
        Telegram telegram) {

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

    public record Telegram(String botToken, String chatId, Severity minSeverity) {

        public boolean enabled() {
            return botToken != null && !botToken.isBlank() && chatId != null && !chatId.isBlank();
        }
    }
}
