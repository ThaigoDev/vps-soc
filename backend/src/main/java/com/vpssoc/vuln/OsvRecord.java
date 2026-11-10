package com.vpssoc.vuln;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.*;

/** The fields of an OSV advisory the SOC uses, parsed from the raw JSON map. */
public record OsvRecord(String id, String summary, List<String> aliases, Vulnerability.Level severity, Instant published,
                        Map<String, List<String>> fixedByPackage) {

    @SuppressWarnings("unchecked")
    public static OsvRecord parse(Map<String, Object> m) {
        String id = String.valueOf(m.get("id"));
        String summary = m.get("summary") != null ? m.get("summary").toString()
                : m.get("details") != null ? firstLine(m.get("details").toString()) : null;
        List<String> aliases = m.get("aliases") instanceof List<?> l ? l.stream().map(String::valueOf).toList() : List.of();

        Vulnerability.Level level = Vulnerability.Level.UNKNOWN;
        if (m.get("database_specific") instanceof Map<?, ?> ds && ds.get("severity") != null) {
            level = level(ds.get("severity").toString());
        }
        if (level == Vulnerability.Level.UNKNOWN && m.get("severity") instanceof List<?> sev) {
            for (Object s : sev) {
                if (s instanceof Map<?, ?> sm && String.valueOf(sm.get("type")).startsWith("CVSS_V3")) {
                    level = fromScore(Cvss3.baseScore(String.valueOf(sm.get("score"))));
                }
            }
        }

        Map<String, List<String>> fixed = new HashMap<>();
        if (m.get("affected") instanceof List<?> affected) {
            for (Object a : affected) {
                if (!(a instanceof Map<?, ?> am) || !(am.get("package") instanceof Map<?, ?> pkg)) {
                    continue;
                }
                if (!"npm".equalsIgnoreCase(String.valueOf(pkg.get("ecosystem")))) {
                    continue;
                }
                String name = String.valueOf(pkg.get("name"));
                if (am.get("ranges") instanceof List<?> ranges) {
                    for (Object r : ranges) {
                        if (r instanceof Map<?, ?> rm && rm.get("events") instanceof List<?> events) {
                            for (Object e : events) {
                                if (e instanceof Map<?, ?> em && em.get("fixed") != null) {
                                    fixed.computeIfAbsent(name, k -> new ArrayList<>()).add(em.get("fixed").toString());
                                }
                            }
                        }
                    }
                }
            }
        }
        Instant published = null;
        if (m.get("published") != null) {
            try {
                published = Instant.parse(m.get("published").toString());
            } catch (DateTimeParseException ignored) {
                // leave empty
            }
        }
        return new OsvRecord(id, summary, aliases, level, published, fixed);
    }

    /** The lowest fix above the installed version, for this package. */
    public String fixFor(String pkg, String installed) {
        return fixedByPackage.getOrDefault(pkg, List.of()).stream()
                .filter(f -> compare(f, installed) > 0)
                .min(OsvRecord::compare)
                .orElse(null);
    }

    public String cve() {
        return aliases.stream().filter(a -> a.startsWith("CVE-")).findFirst().orElse(null);
    }

    static Vulnerability.Level level(String s) {
        return switch (s.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> Vulnerability.Level.CRITICAL;
            case "HIGH" -> Vulnerability.Level.HIGH;
            case "MODERATE", "MEDIUM" -> Vulnerability.Level.MEDIUM;
            case "LOW" -> Vulnerability.Level.LOW;
            default -> Vulnerability.Level.UNKNOWN;
        };
    }

    static Vulnerability.Level fromScore(double score) {
        if (score >= 9.0) return Vulnerability.Level.CRITICAL;
        if (score >= 7.0) return Vulnerability.Level.HIGH;
        if (score >= 4.0) return Vulnerability.Level.MEDIUM;
        if (score > 0) return Vulnerability.Level.LOW;
        return Vulnerability.Level.UNKNOWN;
    }

    /** Numeric semver comparison of the release part; pre-release tags sort before the release. */
    static int compare(String a, String b) {
        String[] pa = a.split("[-+]", 2), pb = b.split("[-+]", 2);
        String[] na = pa[0].split("\\."), nb = pb[0].split("\\.");
        for (int i = 0; i < Math.max(na.length, nb.length); i++) {
            long x = i < na.length ? num(na[i]) : 0, y = i < nb.length ? num(nb[i]) : 0;
            if (x != y) {
                return Long.compare(x, y);
            }
        }
        if (pa.length != pb.length) {
            return pa.length < pb.length ? 1 : -1;
        }
        return pa.length == 2 ? pa[1].compareTo(pb[1]) : 0;
    }

    private static long num(String s) {
        try {
            return Long.parseLong(s.replaceAll("\\D.*", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String firstLine(String s) {
        String line = s.strip().split("\n", 2)[0];
        return line.length() > 300 ? line.substring(0, 300) : line;
    }

    /** CVSS v3.x base score from a vector string (used when the advisory has no severity label). */
    static final class Cvss3 {
        static double baseScore(String vector) {
            Map<String, String> v = new HashMap<>();
            for (String part : vector.split("/")) {
                String[] kv = part.split(":", 2);
                if (kv.length == 2) {
                    v.put(kv[0], kv[1]);
                }
            }
            try {
                double av = switch (v.get("AV")) { case "N" -> 0.85; case "A" -> 0.62; case "L" -> 0.55; default -> 0.2; };
                double ac = "L".equals(v.get("AC")) ? 0.77 : 0.44;
                boolean changed = "C".equals(v.get("S"));
                double pr = switch (v.get("PR")) { case "N" -> 0.85; case "L" -> changed ? 0.68 : 0.62; default -> changed ? 0.5 : 0.27; };
                double ui = "N".equals(v.get("UI")) ? 0.85 : 0.62;
                double c = cia(v.get("C")), i = cia(v.get("I")), a = cia(v.get("A"));
                double iss = 1 - (1 - c) * (1 - i) * (1 - a);
                double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
                double exploit = 8.22 * av * ac * pr * ui;
                if (impact <= 0) {
                    return 0;
                }
                double raw = changed ? Math.min(1.08 * (impact + exploit), 10) : Math.min(impact + exploit, 10);
                return Math.ceil(raw * 10) / 10;
            } catch (RuntimeException e) {
                return 0;
            }
        }

        private static double cia(String s) {
            return switch (s) { case "H" -> 0.56; case "L" -> 0.22; default -> 0; };
        }
    }
}
