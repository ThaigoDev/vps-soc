package com.vpssoc.detection.rules;

import com.vpssoc.detection.Detection;
import com.vpssoc.detection.DetectionRule;
import com.vpssoc.detection.Mitre;
import com.vpssoc.domain.EventType;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.domain.Severity;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * File integrity changes reported by the agent, one incident per file (rule by file class).
 * During an active compromise incident on the host the change is also correlated into it:
 * dropping an SSH key, a cron job or a sudoers entry is the persistence step after the login.
 */
@Component
public class FileIntegrityRules implements DetectionRule {

    /** sshd directives that weaken authentication or add a key source when they are added. */
    private static final Pattern RISKY_SSHD = Pattern.compile(
            "(?i)^(PermitRootLogin\\s+yes|PasswordAuthentication\\s+yes|PermitEmptyPasswords\\s+yes"
                    + "|AuthorizedKeysFile\\s|AuthorizedKeysCommand\\s).*");

    /** Longest lifetime of a key still treated as a provider console session key. */
    static final Duration TEMPORARY_KEY_TTL = Duration.ofHours(1);

    private record FileClass(String ruleId, String label, String[] techniques) {
    }

    @Override
    public Set<EventType> triggers() {
        return EventType.FILE_CHANGES;
    }

    @Override
    public List<Detection> evaluate(SecurityEvent e) {
        String path = e.meta("path") == null ? null : e.meta("path").toString();
        if (path == null) {
            return List.of();
        }
        FileClass fc = classify(path);
        if (fc == null) {
            return List.of();
        }
        EventType type = e.getType();
        String verb = switch (type) {
            case FILE_CREATED -> "criado";
            case FILE_DELETED -> "removido";
            default -> "alterado";
        };

        List<Map<?, ?>> addedKeys = keys(e.meta("addedKeys"));
        List<Map<?, ?>> removedKeys = keys(e.meta("removedKeys"));
        if (RuleIds.FIM_AUTHORIZED_KEYS.equals(fc.ruleId()) && onlyTemporaryKeys(e, addedKeys, removedKeys)) {
            // Provider web consoles (e.g. Hostinger's hPanel terminal) add a key that expires within
            // minutes and drop it later. The event stays in the log; it is not an incident.
            return List.of();
        }

        Severity severity;
        int risk;
        List<String> notes = new ArrayList<>();
        switch (fc.ruleId()) {
            case RuleIds.FIM_AUTHORIZED_KEYS -> {
                severity = type == EventType.FILE_DELETED ? Severity.MEDIUM : Severity.HIGH;
                risk = type == EventType.FILE_DELETED ? 40 : 75;
                notes.add("Uma chave nova permite login sem senha e sobrevive à troca de senha.");
            }
            case RuleIds.FIM_SSHD_CONFIG -> {
                List<String> risky = lines(e.meta("addedLines")).stream().filter(l -> RISKY_SSHD.matcher(l).matches()).toList();
                severity = risky.isEmpty() ? Severity.MEDIUM : Severity.HIGH;
                risk = risky.isEmpty() ? 40 : 75;
                if (!risky.isEmpty()) {
                    notes.add("Diretivas que enfraquecem o SSH: " + String.join("; ", risky) + ".");
                }
            }
            case RuleIds.FIM_SUDOERS -> {
                severity = Severity.HIGH;
                risk = 75;
            }
            case RuleIds.FIM_CRON -> {
                severity = type == EventType.FILE_CREATED ? Severity.HIGH : Severity.MEDIUM;
                risk = type == EventType.FILE_CREATED ? 65 : 45;
            }
            default -> {
                severity = Severity.MEDIUM;
                risk = 40;
            }
        }
        if (worldWritable(e.meta("mode"))) {
            severity = Severity.max(severity, Severity.HIGH);
            risk = Math.max(risk, 70);
            notes.add("O arquivo ficou gravável por qualquer usuário (%s).".formatted(e.meta("mode")));
        }

        List<String> added = lines(e.meta("addedLines"));
        List<String> removed = lines(e.meta("removedLines"));
        StringBuilder desc = new StringBuilder("%s %s (dono %s, %s bytes). Hash %s → %s.".formatted(
                path, verb, e.meta("owner"), e.meta("size"), shortHash(e.meta("oldHash")), shortHash(e.meta("newHash"))));
        if (!added.isEmpty()) {
            desc.append(" Linhas adicionadas: ").append(String.join("; ", added)).append('.');
        }
        if (!removed.isEmpty()) {
            desc.append(" Linhas removidas: ").append(String.join("; ", removed)).append('.');
        }
        if (!addedKeys.isEmpty()) {
            desc.append(" Chaves adicionadas: ").append(String.join("; ", addedKeys.stream().map(FileIntegrityRules::describeKey).toList())).append('.');
        }
        if (!removedKeys.isEmpty()) {
            desc.append(" Chaves removidas: ").append(String.join("; ", removedKeys.stream().map(FileIntegrityRules::describeKey).toList())).append('.');
        }
        notes.forEach(n -> desc.append(' ').append(n));

        return List.of(
                Detection.raise(e.getHostId(), fc.ruleId(), path)
                        .title("%s %s: %s".formatted(fc.label(), verb, path))
                        .description(desc.toString())
                        .severity(severity)
                        .risk(risk)
                        .techniques(fc.techniques())
                        .username(accountOf(path))
                        .build(),
                Detection.attachIfActive(e.getHostId(), RuleIds.SSH_COMPROMISE, null)
                        .techniques(fc.techniques())
                        .risk(100)
                        .build());
    }

    static FileClass classify(String path) {
        if (path.endsWith("/.ssh/authorized_keys")) {
            return new FileClass(RuleIds.FIM_AUTHORIZED_KEYS, "Arquivo authorized_keys", new String[]{Mitre.SSH_AUTHORIZED_KEYS});
        }
        if (path.equals("/etc/ssh/sshd_config") || path.startsWith("/etc/ssh/sshd_config.d/")) {
            return new FileClass(RuleIds.FIM_SSHD_CONFIG, "Arquivo de configuração do sshd", new String[]{Mitre.SSH_AUTHORIZED_KEYS});
        }
        if (path.equals("/etc/sudoers") || path.startsWith("/etc/sudoers.d/")) {
            return new FileClass(RuleIds.FIM_SUDOERS, "Arquivo sudoers", new String[]{Mitre.SUDO});
        }
        if (path.equals("/etc/crontab") || path.startsWith("/etc/cron.d/") || path.startsWith("/var/spool/cron/")) {
            return new FileClass(RuleIds.FIM_CRON, "Arquivo de cron", new String[]{Mitre.CRON});
        }
        if (Set.of("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow").contains(path)) {
            return new FileClass(RuleIds.FIM_ACCOUNTS, "Arquivo de contas", new String[]{Mitre.CREATE_LOCAL_ACCOUNT, Mitre.ACCOUNT_MANIPULATION});
        }
        return null;
    }

    /** The account an authorized_keys file belongs to (/root/... or /home/<user>/...). */
    private static String accountOf(String path) {
        if (!path.endsWith("/.ssh/authorized_keys")) {
            return null;
        }
        if (path.startsWith("/root/")) {
            return "root";
        }
        String[] parts = path.split("/");
        return parts.length > 2 && "home".equals(parts[1]) ? parts[2] : null;
    }

    private static boolean worldWritable(Object mode) {
        String m = mode == null ? "" : mode.toString();
        return m.length() == 10 && m.charAt(8) == 'w';
    }

    /**
     * True when the change only adds or removes keys that expire within {@link #TEMPORARY_KEY_TTL}
     * of the event, and nothing else about the file (owner, mode) changed. A key without
     * expiry-time, or with a long one, never qualifies, so a planted backdoor key still alerts.
     */
    static boolean onlyTemporaryKeys(SecurityEvent e, List<Map<?, ?>> added, List<Map<?, ?>> removed) {
        if (added.isEmpty() && removed.isEmpty()) {
            return false;
        }
        if (e.meta("oldOwner") != null || e.meta("oldMode") != null || worldWritable(e.meta("mode"))) {
            return false;
        }
        Instant limit = e.getOccurredAt().plus(TEMPORARY_KEY_TTL);
        for (List<Map<?, ?>> list : List.of(added, removed)) {
            for (Map<?, ?> k : list) {
                Instant exp = expiry(k);
                if (exp == null || exp.isAfter(limit)) {
                    return false;
                }
            }
        }
        return true;
    }

    private static Instant expiry(Map<?, ?> key) {
        Object v = key.get("expiresAt");
        if (v == null) {
            return null;
        }
        try {
            return Instant.parse(v.toString());
        } catch (DateTimeParseException ex) {
            return null;
        }
    }

    private static String describeKey(Map<?, ?> k) {
        StringBuilder s = new StringBuilder();
        s.append(k.get("type"));
        if (k.get("bits") != null) {
            s.append(' ').append(k.get("bits"));
        }
        s.append(' ').append(k.get("fingerprint"));
        if (k.get("comment") != null && !k.get("comment").toString().isBlank()) {
            s.append(" \"").append(k.get("comment")).append('"');
        }
        Instant exp = expiry(k);
        if (exp != null) {
            s.append(" (expira ").append(exp).append(')');
        }
        return s.toString();
    }

    private static List<Map<?, ?>> keys(Object v) {
        if (v instanceof List<?> l) {
            return l.stream().filter(Map.class::isInstance).<Map<?, ?>>map(Map.class::cast).toList();
        }
        return List.of();
    }

    private static List<String> lines(Object v) {
        if (v instanceof List<?> l) {
            return l.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    private static String shortHash(Object h) {
        if (h == null) {
            return "-";
        }
        String s = h.toString();
        return s.length() > 12 ? s.substring(0, 12) : s;
    }
}
