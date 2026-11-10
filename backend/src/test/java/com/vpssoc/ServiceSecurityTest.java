package com.vpssoc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vpssoc.vuln.OsvClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Service security: dependency vulnerabilities (OSV mocked), checks, score, debugger, certificates, probes. */
@SpringBootTest(properties = {
        "soc.agent-token=test-agent-token-0123456789abcdef",
        "soc.dashboard-token=test-dashboard-token-0123456789ab"})
@AutoConfigureMockMvc
@Testcontainers
class ServiceSecurityTest {

    private static final String AGENT = "Bearer test-agent-token-0123456789abcdef";
    private static final String DASH = "Bearer test-dashboard-token-0123456789ab";

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;
    @MockitoBean
    OsvClient osv;

    private static final Map<String, List<String>> ADVISORIES = Map.of(
            "lodash@4.17.15", List.of("GHSA-p6mc-m468-83gw"),
            "jest@29.0.0", List.of("GHSA-dev-only"));

    @Test
    void vulnerabilitiesChecksScoreAndRecovery() throws Exception {
        when(osv.queryBatch(any())).thenAnswer(inv -> {
            List<OsvClient.PackageVersion> q = inv.getArgument(0);
            return q.stream().map(p -> ADVISORIES.getOrDefault(p.name() + "@" + p.version(), List.<String>of())).toList();
        });
        when(osv.vulnerability(anyString())).thenAnswer(inv -> advisory(inv.getArgument(0)));

        String host = "vps-sec-1";
        Instant certEnd = Instant.now().plusSeconds(2 * 86_400);
        heartbeat(host, app(Map.of("inspect", "--inspect=0.0.0.0:9229", "nodeEnv", "development",
                        "envFile", "/home/proj/api/.env", "envFileMode", "-rw-r--r--", "lockfile", "/home/proj/api/package-lock.json"),
                Map.of("ok", true, "port", 3000, "status", 200, "latencyMs", 12)), certEnd);

        upload(host, List.of(pkg("express", "4.21.2", false), pkg("lodash", "4.17.15", false), pkg("jest", "29.0.0", true)), "hash-1");
        String res = mvc.perform(post("/api/v1/services/" + host + "/api/scan").header("Authorization", DASH))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(res).get("vulnerable").asInt()).isEqualTo(2);

        JsonNode open = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        JsonNode vuln = byRule(open, "SERVICE_VULNERABLE", host);
        assertThat(vuln.get("severity").asText()).isEqualTo("HIGH"); // critical in production code
        assertThat(vuln.get("service").asText()).isEqualTo("api");
        assertThat(byRule(open, "SERVICE_DEBUG_EXPOSED", host).get("severity").asText()).isEqualTo("CRITICAL");
        assertThat(byRule(open, "CERT_EXPIRING", host).get("severity").asText()).isEqualTo("HIGH");

        JsonNode ex = getJson("/api/v1/incidents/" + vuln.get("id").asLong()).get("explanation");
        assertThat(ex.get("summary").asText()).contains("1 crítica");
        assertThat(ex.get("evidence").findValuesAsText("value")).anyMatch(v -> v.contains("4.17.21") && v.contains("CVE-2020-8203"));
        assertThat(ex.get("recommendations").findValuesAsText("command")).anyMatch(c -> c.contains("cd /home/proj/api && npm audit"));

        JsonNode svc = service(host, "api");
        assertThat(svc.get("vulnerabilities").get("CRITICAL").asInt()).isEqualTo(1); // dev-only jest not counted
        Map<String, String> checks = new HashMap<>();
        svc.get("checks").forEach(c -> checks.put(c.get("key").asText(), c.get("status").asText()));
        assertThat(checks).containsEntry("deps", "FAIL").containsEntry("debug", "FAIL").containsEntry("node", "FAIL")
                .containsEntry("user", "WARN").containsEntry("bind", "WARN").containsEntry("tls", "WARN")
                .containsEntry("env", "WARN").containsEntry("nodeenv", "WARN").containsEntry("probe", "OK");
        assertThat(svc.get("securityScore").asInt()).isLessThan(30);

        JsonNode detail = getJson("/api/v1/services/" + host + "/api");
        JsonNode lodash = null;
        for (JsonNode v : detail.get("vulnerabilities")) {
            if ("lodash".equals(v.get("pkg").asText())) lodash = v;
        }
        assertThat(lodash.get("fixedVersion").asText()).isEqualTo("4.17.21");
        assertThat(lodash.get("cve").asText()).isEqualTo("CVE-2020-8203");
        assertThat(detail.get("inventory").get("packages").asInt()).isEqualTo(3);

        // Upgrade lodash: the finding is resolved and the incident closes itself.
        upload(host, List.of(pkg("express", "4.21.2", false), pkg("lodash", "4.17.21", false), pkg("jest", "29.0.0", true)), "hash-2");
        mvc.perform(post("/api/v1/services/" + host + "/api/scan").header("Authorization", DASH)).andExpect(status().isOk());
        for (JsonNode n : getJson("/api/v1/incidents?status=OPEN&size=200").get("content")) {
            if (host.equals(n.get("hostId").asText())) {
                assertThat(n.get("ruleId").asText()).isNotEqualTo("SERVICE_VULNERABLE");
            }
        }
        assertThat(service(host, "api").get("vulnerabilities").get("CRITICAL").asInt()).isZero();
    }

    @Test
    void unresponsiveAppNeedsTwoFailedChecks() throws Exception {
        String host = "vps-sec-2";
        Map<String, Object> bad = Map.of("ok", false, "port", 3000, "error", "context deadline exceeded", "latencyMs", 5000);
        heartbeat(host, app(Map.of("nodeEnv", "production"), bad), null);
        assertThat(rules(host)).doesNotContain("SERVICE_NOT_RESPONDING");
        heartbeat(host, app(Map.of("nodeEnv", "production"), bad), null);
        assertThat(rules(host)).contains("SERVICE_NOT_RESPONDING");
        heartbeat(host, app(Map.of("nodeEnv", "production"), Map.of("ok", true, "port", 3000, "status", 200, "latencyMs", 8)), null);
        assertThat(rules(host)).doesNotContain("SERVICE_NOT_RESPONDING");
    }

    // ---------------------------------------------------------------- helpers

    private static Map<String, Object> advisory(String id) {
        if (id.equals("GHSA-p6mc-m468-83gw")) {
            return Map.of("id", id, "summary", "Prototype Pollution in lodash", "aliases", List.of("CVE-2020-8203"),
                    "published", "2020-07-15T19:15:00Z", "database_specific", Map.of("severity", "CRITICAL"),
                    "affected", List.of(Map.of("package", Map.of("name", "lodash", "ecosystem", "npm"),
                            "ranges", List.of(Map.of("type", "SEMVER", "events", List.of(Map.of("introduced", "0"), Map.of("fixed", "4.17.21")))))));
        }
        return Map.of("id", id, "summary", "dev tool issue", "severity",
                List.of(Map.of("type", "CVSS_V3", "score", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")));
    }

    private Map<String, Object> app(Map<String, Object> security, Map<String, Object> probe) {
        Map<String, Object> m = new HashMap<>();
        m.put("source", "pm2");
        m.put("name", "api");
        m.put("pmId", 0);
        m.put("pid", 2001);
        m.put("status", "online");
        m.put("restarts", 0);
        m.put("cpuPercent", 1.0);
        m.put("memoryBytes", 100L << 20);
        m.put("user", "root");
        m.put("nodeVersion", "20.11.0");
        m.put("cwd", "/home/proj/api");
        m.put("pm2Home", "/root/.pm2");
        m.put("ports", List.of(3000));
        m.put("listeners", List.of(Map.of("address", "0.0.0.0", "port", 3000)));
        m.put("security", security);
        m.put("probe", probe);
        m.put("errorLines", 0);
        return m;
    }

    private void heartbeat(String host, Map<String, Object> app, Instant certEnd) throws Exception {
        Map<String, Object> a = new HashMap<>(app);
        Map<String, Object> posture = new HashMap<>();
        posture.put("sessions", List.of());
        if (certEnd != null) {
            Map<String, Object> cert = Map.of("path", "/etc/letsencrypt/live/api.example.com/fullchain.pem", "subject", "api.example.com",
                    "issuer", "Let's Encrypt R11", "dnsNames", List.of("api.example.com"), "notAfter", certEnd.toString());
            a.put("sites", List.of(Map.of("domains", List.of("api.example.com"), "proxyPorts", List.of(3000), "tls", true,
                    "certificate", cert, "configFile", "/etc/nginx/sites-enabled/api")));
            posture.put("certificates", List.of(cert));
        }
        String body = json.writeValueAsString(Map.of("hostId", host, "hostname", host, "os", "Ubuntu 24.04", "agentVersion", "test",
                "heartbeatIntervalSeconds", 30, "metrics", Map.of("memTotalBytes", 4L << 30), "openPorts", List.of(),
                "posture", posture, "services", List.of(a)));
        mvc.perform(post("/api/v1/ingest/heartbeat").header("Authorization", AGENT)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isNoContent());
    }

    private void upload(String host, List<Map<String, Object>> pkgs, String hash) throws Exception {
        String body = json.writeValueAsString(Map.of("hostId", host, "service", "api", "pm2Home", "/root/.pm2",
                "lockfile", "/home/proj/api/package-lock.json", "hash", hash, "packages", pkgs));
        mvc.perform(post("/api/v1/ingest/inventory").header("Authorization", AGENT)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isAccepted());
    }

    private static Map<String, Object> pkg(String name, String version, boolean dev) {
        return Map.of("name", name, "version", version, "dev", dev);
    }

    private JsonNode service(String host, String name) throws Exception {
        for (JsonNode s : getJson("/api/v1/services")) {
            if (host.equals(s.get("hostId").asText()) && name.equals(s.get("pm2").get("name").asText())) return s;
        }
        throw new AssertionError("service not found");
    }

    private List<String> rules(String host) throws Exception {
        List<String> out = new ArrayList<>();
        for (JsonNode n : getJson("/api/v1/incidents?status=OPEN&size=200").get("content")) {
            if (host.equals(n.get("hostId").asText())) out.add(n.get("ruleId").asText());
        }
        return out;
    }

    private JsonNode getJson(String url) throws Exception {
        String res = mvc.perform(get(url).header("Authorization", DASH))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(res);
    }

    private static JsonNode byRule(JsonNode incidents, String ruleId, String hostId) {
        for (JsonNode n : incidents) {
            if (ruleId.equals(n.get("ruleId").asText()) && hostId.equals(n.get("hostId").asText())) return n;
        }
        throw new AssertionError("no incident for rule " + ruleId + " on " + hostId + " in " + incidents);
    }
}
