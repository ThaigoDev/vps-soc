package com.vpssoc.notification;

import com.vpssoc.config.SocProperties;
import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.Incident;
import com.vpssoc.domain.ResponseAction;
import com.vpssoc.incident.IncidentNotification;
import com.vpssoc.insight.Explanation;
import com.vpssoc.insight.IncidentExplainer;
import com.vpssoc.insight.InsightService;
import com.vpssoc.repository.IncidentRepository;
import com.vpssoc.repository.ResponseActionRepository;
import com.vpssoc.response.ActionNotification;
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

/**
 * Sends incidents and response actions to a Telegram chat after the transaction that
 * created them commits. Incident alerts carry the same explanation the dashboard shows,
 * shortened: what happened, why it matters and the first thing to do.
 */
@Component
public class TelegramNotifier {

    private static final Logger log = LoggerFactory.getLogger(TelegramNotifier.class);
    private static final int MAX_TEXT = 3800; // Telegram's limit is 4096

    private final SocProperties.Telegram cfg;
    private final IncidentRepository incidents;
    private final ResponseActionRepository actions;
    private final InsightService insights;
    private final RestClient http;

    public TelegramNotifier(SocProperties props, IncidentRepository incidents, ResponseActionRepository actions,
                            InsightService insights, RestClient.Builder builder) {
        this.cfg = props.telegram();
        this.incidents = incidents;
        this.actions = actions;
        this.insights = insights;
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
        Explanation e = null;
        try {
            e = insights.insight(inc).explanation();
        } catch (RuntimeException ex) {
            log.warn("Could not build explanation for incident #{}: {}", inc.getId(), ex.toString());
        }
        send(format(inc, n.kind(), e), "incident #" + inc.getId());
    }

    /**
     * Response activity: an approval the operator must give, and the outcome of actions on
     * incidents that are alert-worthy (so a blocked attacker is reported, routine noise is not).
     */
    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onAction(ActionNotification n) {
        if (!cfg.enabled() || n.kind() == ActionNotification.Kind.QUEUED) {
            return;
        }
        ResponseAction a = actions.findById(n.actionId()).orElse(null);
        if (a == null) {
            return;
        }
        Incident inc = a.getIncidentId() == null ? null : incidents.findById(a.getIncidentId()).orElse(null);
        boolean relevant = n.kind() == ActionNotification.Kind.NEEDS_APPROVAL
                || a.getStatus() != ResponseAction.Status.SUCCEEDED
                || inc == null || inc.getSeverity().atLeast(cfg.minSeverity());
        if (relevant) {
            send(formatAction(a, inc, n.kind()), "action #" + a.getId());
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
        return send("✅ <b>VPS-SOC</b>\nTeste do canal de alertas. Incidentes " + cfg.minSeverity()
                + " ou acima chegam aqui, mesmo com o painel fechado.", "test") ? TestResult.SENT : TestResult.FAILED;
    }

    private boolean send(String text, String what) {
        try {
            http.post()
                    .uri("/bot{token}/sendMessage", cfg.botToken())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("chat_id", cfg.chatId(), "parse_mode", "HTML", "disable_web_page_preview", true,
                            "text", text.length() > MAX_TEXT ? text.substring(0, MAX_TEXT) + "…" : text))
                    .retrieve()
                    .toBodilessEntity();
            return true;
        } catch (Exception e) {
            // Never log the exception message: it contains the URL with the bot token.
            log.warn("Telegram notification for {} failed ({})", what, e.getClass().getSimpleName());
            return false;
        }
    }

    static String format(Incident inc, IncidentNotification.Kind kind, Explanation e) {
        String techniques = inc.getTechniques().stream()
                .map(t -> t + " " + Mitre.name(t))
                .collect(Collectors.joining("\n• ", "• ", ""));
        StringBuilder sb = new StringBuilder();
        sb.append("%s <b>%s%s</b> · risco <b>%d/100</b>\n".formatted(icon(inc), kind == IncidentNotification.Kind.ESCALATED ? "ESCALADO → " : "",
                inc.getSeverity(), inc.getRiskScore()));
        sb.append("<b>#%d %s</b>\n".formatted(inc.getId(), esc(inc.getTitle())));
        sb.append("Host <code>%s</code>".formatted(esc(inc.getHostId())));
        if (inc.getSourceIp() != null) {
            sb.append(" · IP <code>").append(esc(inc.getSourceIp())).append("</code>");
        }
        if (inc.getUsername() != null) {
            sb.append(" · usuário <code>").append(esc(inc.getUsername())).append("</code>");
        }
        sb.append("\n\n");
        if (e != null && e.summary() != null) {
            sb.append("<b>O que aconteceu</b>\n").append(esc(e.summary())).append("\n\n");
            if (e.impact() != null) {
                sb.append("<b>Por que importa</b>\n").append(esc(e.impact())).append("\n\n");
            }
            if (e.response() != null) {
                sb.append("<b>Resposta</b>\n").append(esc(e.response())).append("\n\n");
            }
            if (!e.recommendations().isEmpty()) {
                Explanation.Step first = e.recommendations().getFirst();
                sb.append("<b>Primeiro passo</b>\n").append(esc(first.title()));
                if (first.command() != null) {
                    sb.append("\n<code>").append(esc(first.command())).append("</code>");
                }
                sb.append("\n\n");
            }
        } else if (inc.getDescription() != null) {
            sb.append(esc(inc.getDescription())).append("\n\n");
        }
        if (!inc.getTechniques().isEmpty()) {
            sb.append("MITRE ATT&amp;CK:\n").append(esc(techniques));
        }
        return sb.toString().strip();
    }

    static String formatAction(ResponseAction a, Incident inc, ActionNotification.Kind kind) {
        String label = esc(IncidentExplainer.actionLabel(a));
        String ref = inc == null ? "" : "\nIncidente <b>#%d</b> %s".formatted(inc.getId(), esc(inc.getTitle()));
        if (kind == ActionNotification.Kind.NEEDS_APPROVAL) {
            return "⏳ <b>Aprovação necessária</b> · ação #%d\n%s%s\n\n%s\n\nAbra o painel → Resposta para aprovar ou descartar."
                    .formatted(a.getId(), label, ref, esc(String.valueOf(a.getReason())));
        }
        String head = switch (a.getStatus()) {
            case SUCCEEDED -> "🛡️ <b>Contenção executada</b>";
            case REJECTED -> "⚠️ <b>O agente recusou a ação</b>";
            default -> "❌ <b>Ação de resposta falhou</b>";
        };
        String who = a.getOrigin() == ResponseAction.Origin.AGENT ? "pelo próprio agente (guarda local)"
                : a.getMode() == ResponseAction.Mode.AUTO ? "automaticamente" : "após sua aprovação";
        return "%s · ação #%d\n%s, %s%s\n\n%s".formatted(head, a.getId(), label, who, ref, esc(String.valueOf(a.getResult())));
    }

    private static String icon(Incident inc) {
        return switch (inc.getSeverity()) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            default -> "🟢";
        };
    }

    private static String esc(String s) {
        return HtmlUtils.htmlEscape(s == null ? "" : s);
    }
}
