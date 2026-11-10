package com.vpssoc.service;

import com.vpssoc.vuln.ServiceInventory;
import com.vpssoc.vuln.Vulnerability;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.*;

/**
 * The security checklist and 0–100 score of one PM2 app: dependency vulnerabilities, Node.js
 * runtime support, debugger exposure, privileges, network exposure, HTTPS and certificates,
 * secrets file permissions, NODE_ENV, and whether it answers.
 */
public final class ServiceSecurity {

    public enum CheckStatus { OK, WARN, FAIL, INFO }

    public record Check(String key, String label, CheckStatus status, String detail, String fix) {
    }

    /** Node.js release lines and their end of security support (nodejs.org/en/about/previous-releases). */
    static final Map<Integer, LocalDate> NODE_EOL = Map.ofEntries(
            Map.entry(12, LocalDate.of(2022, 4, 30)), Map.entry(14, LocalDate.of(2023, 4, 30)),
            Map.entry(16, LocalDate.of(2023, 9, 11)), Map.entry(17, LocalDate.of(2022, 6, 1)),
            Map.entry(18, LocalDate.of(2025, 4, 30)), Map.entry(19, LocalDate.of(2023, 6, 1)),
            Map.entry(20, LocalDate.of(2026, 4, 30)), Map.entry(21, LocalDate.of(2024, 6, 1)),
            Map.entry(22, LocalDate.of(2027, 4, 30)), Map.entry(23, LocalDate.of(2025, 6, 1)),
            Map.entry(24, LocalDate.of(2028, 4, 30)), Map.entry(25, LocalDate.of(2026, 6, 1)),
            Map.entry(26, LocalDate.of(2029, 4, 30)));

    private ServiceSecurity() {
    }

    public static List<Check> checks(Map<String, Object> app, Map<Vulnerability.Level, Long> vulns, ServiceInventory inv,
                                     Double probeOkPct, long errorsLastHour, Instant now) {
        List<Check> out = new ArrayList<>();
        String name = String.valueOf(app.get("name"));
        Map<?, ?> sec = app.get("security") instanceof Map<?, ?> m ? m : Map.of();

        // 1. Dependencies
        if (inv == null) {
            out.add(new Check("deps", "Dependências com falhas conhecidas", CheckStatus.INFO,
                    sec.get("lockfile") == null ? "Sem package-lock.json: não dá para listar as dependências instaladas"
                            : "Aguardando o agente enviar a lista de pacotes",
                    sec.get("lockfile") == null ? "Gere o lockfile no diretório do app: npm install --package-lock-only" : null));
        } else {
            long c = vulns.getOrDefault(Vulnerability.Level.CRITICAL, 0L), h = vulns.getOrDefault(Vulnerability.Level.HIGH, 0L),
                    md = vulns.getOrDefault(Vulnerability.Level.MEDIUM, 0L), l = vulns.getOrDefault(Vulnerability.Level.LOW, 0L);
            int pkgs = inv.getPackages() == null ? 0 : inv.getPackages().size();
            CheckStatus st = c + h > 0 ? CheckStatus.FAIL : md > 0 ? CheckStatus.WARN : CheckStatus.OK;
            out.add(new Check("deps", "Dependências com falhas conhecidas", st,
                    c + h + md + l == 0 ? "%d pacotes verificados, nenhuma falha conhecida".formatted(pkgs)
                            : "%d crítica(s), %d alta(s), %d média(s), %d baixa(s) em %d pacotes".formatted(c, h, md, l, pkgs),
                    st == CheckStatus.OK ? null : "cd %s && npm audit fix (e revise as quebras de versão maior com npm audit)".formatted(dir(app))));
        }

        // 2. Node.js runtime
        String nodeVersion = String.valueOf(app.getOrDefault("nodeVersion", ""));
        Integer major = nodeMajor(nodeVersion);
        LocalDate eol = major == null ? null : NODE_EOL.get(major);
        LocalDate today = LocalDate.ofInstant(now, ZoneOffset.UTC);
        if (eol == null) {
            out.add(new Check("node", "Node.js com suporte de segurança", CheckStatus.INFO,
                    major == null ? "Versão do Node não informada" : "Node " + nodeVersion + ": data de fim de suporte desconhecida", null));
        } else if (eol.isBefore(today)) {
            out.add(new Check("node", "Node.js com suporte de segurança", CheckStatus.FAIL,
                    "Node %s está sem correções de segurança desde %s".formatted(nodeVersion, eol),
                    "Migre para o Node 22 ou 24 (LTS) e reinicie o app: nvm install 24 && pm2 restart " + name + " --update-env"));
        } else if (eol.isBefore(today.plusMonths(6))) {
            out.add(new Check("node", "Node.js com suporte de segurança", CheckStatus.WARN,
                    "Node %s perde o suporte em %s".formatted(nodeVersion, eol), "Planeje a migração para a próxima LTS"));
        } else {
            out.add(new Check("node", "Node.js com suporte de segurança", CheckStatus.OK, "Node %s, suportado até %s".formatted(nodeVersion, eol), null));
        }

        // 3. Debugger
        Object inspect = sec.get("inspect");
        out.add(inspect != null && !inspect.toString().isBlank()
                ? new Check("debug", "Debugger desligado", CheckStatus.FAIL, "Roda com " + inspect + ": quem alcança a porta executa código no app",
                "Remova --inspect dos node_args do PM2 e rode: pm2 restart " + name + " --update-env")
                : new Check("debug", "Debugger desligado", CheckStatus.OK, "Sem --inspect", null));

        // 4. Privileges
        boolean root = "root".equals(app.get("user"));
        out.add(root
                ? new Check("user", "Roda sem privilégios de root", CheckStatus.WARN,
                "Roda como root: uma falha no app vira controle total do servidor",
                "Crie um usuário só para o app e suba o PM2 com ele (pm2 startup -u <usuario>)")
                : new Check("user", "Roda sem privilégios de root", CheckStatus.OK, "Usuário " + app.get("user"), null));

        // 5. Network exposure and HTTPS
        List<Map<?, ?>> listeners = list(app.get("listeners"));
        List<Map<?, ?>> sites = list(app.get("sites"));
        List<String> publicPorts = listeners.stream()
                .filter(x -> "0.0.0.0".equals(x.get("address")) || "::".equals(x.get("address")))
                .map(x -> String.valueOf(x.get("port"))).distinct().toList();
        if (listeners.isEmpty()) {
            out.add(new Check("bind", "Porta não exposta direto", CheckStatus.INFO, "O app não escuta em nenhuma porta TCP", null));
        } else if (!publicPorts.isEmpty() && !sites.isEmpty()) {
            out.add(new Check("bind", "Porta não exposta direto", CheckStatus.WARN,
                    "Porta %s aceita conexões de qualquer interface, mas o app já fica atrás do nginx: dá para chegar nele sem passar pelo nginx (nem pelo HTTPS)"
                            .formatted(String.join(", ", publicPorts)),
                    "Faça o app escutar só em 127.0.0.1 (ex.: app.listen(PORT, \"127.0.0.1\")) ou bloqueie a porta no firewall da Hostinger"));
        } else if (!publicPorts.isEmpty()) {
            out.add(new Check("bind", "Porta não exposta direto", CheckStatus.WARN,
                    "Porta %s exposta direto na internet, sem proxy reverso nem HTTPS".formatted(String.join(", ", publicPorts)),
                    "Coloque o app atrás do nginx com HTTPS (certbot --nginx) e faça-o escutar em 127.0.0.1"));
        } else {
            out.add(new Check("bind", "Porta não exposta direto", CheckStatus.OK, "Escuta só localmente", null));
        }
        if (!sites.isEmpty()) {
            List<String> domains = sites.stream().flatMap(s -> list2(s.get("domains")).stream()).distinct().toList();
            boolean tls = sites.stream().anyMatch(s -> Boolean.TRUE.equals(s.get("tls")));
            Instant soonest = null;
            for (Map<?, ?> s : sites) {
                if (s.get("certificate") instanceof Map<?, ?> cert && cert.get("notAfter") != null) {
                    try {
                        Instant na = Instant.parse(cert.get("notAfter").toString());
                        soonest = soonest == null || na.isBefore(soonest) ? na : soonest;
                    } catch (RuntimeException ignored) {
                        // unparsable date: skip
                    }
                }
            }
            if (!tls) {
                out.add(new Check("tls", "HTTPS com certificado válido", CheckStatus.FAIL,
                        "%s só responde em HTTP: senhas e tokens trafegam em texto puro".formatted(String.join(", ", domains)),
                        "sudo certbot --nginx -d " + String.join(" -d ", domains)));
            } else if (soonest != null) {
                long days = Duration.between(now, soonest).toDays();
                CheckStatus st = soonest.isBefore(now) ? CheckStatus.FAIL : days <= 14 ? CheckStatus.WARN : CheckStatus.OK;
                out.add(new Check("tls", "HTTPS com certificado válido", st,
                        soonest.isBefore(now) ? "Certificado de %s VENCIDO".formatted(String.join(", ", domains))
                                : "Certificado de %s vale mais %d dia(s)".formatted(String.join(", ", domains), days),
                        st == CheckStatus.OK ? null : "sudo certbot renew && sudo systemctl reload nginx (veja também: systemctl status certbot.timer)"));
            } else {
                out.add(new Check("tls", "HTTPS com certificado válido", CheckStatus.OK, "HTTPS em " + String.join(", ", domains), null));
            }
        }

        // 6. Secrets file
        Object mode = sec.get("envFileMode");
        if (mode != null && mode.toString().length() == 10) {
            boolean worldReadable = mode.toString().charAt(7) == 'r';
            out.add(worldReadable
                    ? new Check("env", "Arquivo .env protegido", CheckStatus.WARN,
                    "%s tem permissão %s: qualquer usuário do servidor lê as senhas".formatted(sec.get("envFile"), mode),
                    "chmod 600 " + sec.get("envFile"))
                    : new Check("env", "Arquivo .env protegido", CheckStatus.OK, "%s com permissão %s".formatted(sec.get("envFile"), mode), null));
        }

        // 7. NODE_ENV
        Object nodeEnv = sec.get("nodeEnv");
        if (nodeEnv != null && !nodeEnv.toString().isBlank()) {
            out.add("production".equals(nodeEnv)
                    ? new Check("nodeenv", "NODE_ENV=production", CheckStatus.OK, "production", null)
                    : new Check("nodeenv", "NODE_ENV=production", CheckStatus.WARN,
                    "NODE_ENV=%s: frameworks mostram stack traces e mensagens de debug para o usuário".formatted(nodeEnv),
                    "Defina NODE_ENV=production no ecosystem do PM2 e rode pm2 restart %s --update-env".formatted(name)));
        } else {
            out.add(new Check("nodeenv", "NODE_ENV=production", CheckStatus.WARN, "NODE_ENV não definido (o padrão é development)",
                    "Defina NODE_ENV=production no ecosystem do PM2 e rode pm2 restart %s --update-env".formatted(name)));
        }

        // 8. Availability and errors
        if (app.get("probe") instanceof Map<?, ?> p) {
            boolean ok = Boolean.TRUE.equals(p.get("ok"));
            out.add(ok
                    ? new Check("probe", "Responde na porta", CheckStatus.OK,
                    "%s em %s ms%s".formatted(p.get("status") != null && !"0".equals(String.valueOf(p.get("status"))) ? "HTTP " + p.get("status") : "TCP",
                            p.get("latencyMs"), probeOkPct == null ? "" : " · %.1f%% das checagens em 24h".formatted(probeOkPct)), null)
                    : new Check("probe", "Responde na porta", CheckStatus.FAIL, "Falhou: " + p.get("error"),
                    "pm2 logs " + name + " --err --lines 50 --nostream"));
        }
        if (errorsLastHour > 100) {
            out.add(new Check("errors", "Log de erro calmo", CheckStatus.WARN,
                    "%d linhas novas no log de erro na última hora".formatted(errorsLastHour), "pm2 logs " + name + " --err --lines 100 --nostream"));
        }
        return out;
    }

    /** 100 minus the weight of each failed/warned check. */
    public static int score(List<Check> checks, Map<Vulnerability.Level, Long> vulns) {
        int score = 100;
        for (Check c : checks) {
            int w = switch (c.key()) {
                case "deps" -> vulns.getOrDefault(Vulnerability.Level.CRITICAL, 0L) > 0 ? 35 : c.status() == CheckStatus.FAIL ? 25 : 10;
                case "debug" -> 40;
                case "tls" -> 25;
                case "probe" -> 20;
                case "node" -> 20;
                case "bind", "user", "env" -> 10;
                default -> 5;
            };
            if (c.status() == CheckStatus.FAIL) {
                score -= w;
            } else if (c.status() == CheckStatus.WARN) {
                score -= Math.max(3, w / 2);
            }
        }
        return Math.max(0, score);
    }

    static Integer nodeMajor(String v) {
        String s = v.startsWith("v") ? v.substring(1) : v;
        int dot = s.indexOf('.');
        try {
            return Integer.parseInt(dot > 0 ? s.substring(0, dot) : s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String dir(Map<String, Object> app) {
        Object cwd = app.get("cwd");
        return cwd == null || "/".equals(cwd) ? "<pasta do app>" : cwd.toString();
    }

    private static List<Map<?, ?>> list(Object o) {
        if (!(o instanceof List<?> l)) {
            return List.of();
        }
        List<Map<?, ?>> out = new ArrayList<>();
        l.forEach(x -> {
            if (x instanceof Map<?, ?> m) out.add(m);
        });
        return out;
    }

    private static List<String> list2(Object o) {
        return o instanceof List<?> l ? l.stream().map(String::valueOf).toList() : List.of();
    }
}
