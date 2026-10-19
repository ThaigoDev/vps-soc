package com.vpssoc.notification;

import com.vpssoc.config.SocProperties;
import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.Incident;
import com.vpssoc.incident.IncidentNotification;
import com.vpssoc.repository.IncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.HtmlUtils;

import java.util.Map;
import java.util.stream.Collectors;

/** Sends incidents to a Telegram chat after the transaction that created them commits. */
@Component
public class TelegramNotifier {

    private static final Logger log = LoggerFactory.getLogger(TelegramNotifier.class);

    private final SocProperties.Telegram cfg;
    private final IncidentRepository incidents;
    private final RestClient http;

    public TelegramNotifier(SocProperties props, IncidentRepository incidents, RestClient.Builder builder) {
        this.cfg = props.telegram();
        this.incidents = incidents;
        this.http = builder.baseUrl("https://api.telegram.org").build();
        log.info("Telegram notifications {}", cfg.enabled() ? "enabled (min severity " + cfg.minSeverity() + ")" : "disabled");
    }

    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onIncident(IncidentNotification n) {
        if (!cfg.enabled()) {
            return;
        }
        Incident inc = incidents.findById(n.incidentId()).orElse(null);
        if (inc == null || !inc.getSeverity().atLeast(cfg.minSeverity())) {
            return;
        }
        try {
            http.post()
                    .uri("/bot{token}/sendMessage", cfg.botToken())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("chat_id", cfg.chatId(), "parse_mode", "HTML", "text", format(inc, n.kind())))
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception e) {
            // Never log the exception message: it contains the URL with the bot token.
            log.warn("Telegram notification for incident #{} failed ({})", inc.getId(), e.getClass().getSimpleName());
        }
    }

    public enum TestResult { DISABLED, SENT, FAILED }

    public boolean enabled() {
        return cfg.enabled();
    }

    public String minSeverity() {
        return cfg.minSeverity().name();
    }

    /** Sends a test message so the operator can confirm the channel works end to end. */
    public TestResult sendTest() {
        if (!cfg.enabled()) {
            return TestResult.DISABLED;
        }
        try {
            http.post()
                    .uri("/bot{token}/sendMessage", cfg.botToken())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("chat_id", cfg.chatId(), "parse_mode", "HTML",
                            "text", "✅ <b>VPS-SOC</b>\nTeste do canal de alertas. Incidentes " + cfg.minSeverity()
                                    + " ou acima chegam aqui, mesmo com o painel fechado."))
                    .retrieve()
                    .toBodilessEntity();
            return TestResult.SENT;
        } catch (Exception e) {
            log.warn("Telegram test message failed ({})", e.getClass().getSimpleName());
            return TestResult.FAILED;
        }
    }

    static String format(Incident inc, IncidentNotification.Kind kind) {
        String icon = switch (inc.getSeverity()) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            default -> "🟢";
        };
        String techniques = inc.getTechniques().stream()
                .map(t -> t + " " + Mitre.name(t))
                .collect(Collectors.joining("\n• ", "• ", ""));
        return """
                %s <b>%s%s</b>
                <b>#%d</b> %s
                Host: <code>%s</code>%s%s
                Risco: <b>%d/100</b>

                %s
                %s""".formatted(
                icon, kind == IncidentNotification.Kind.ESCALATED ? "ESCALADO → " : "", inc.getSeverity(),
                inc.getId(), esc(inc.getTitle()),
                esc(inc.getHostId()),
                inc.getSourceIp() != null ? "\nIP: <code>" + esc(inc.getSourceIp()) + "</code>" : "",
                inc.getUsername() != null ? "\nUsuário: <code>" + esc(inc.getUsername()) + "</code>" : "",
                inc.getRiskScore(),
                esc(inc.getDescription() == null ? "" : inc.getDescription()),
                inc.getTechniques().isEmpty() ? "" : "\nMITRE ATT&amp;CK:\n" + esc(techniques));
    }

    private static String esc(String s) {
        return HtmlUtils.htmlEscape(s);
    }
}
