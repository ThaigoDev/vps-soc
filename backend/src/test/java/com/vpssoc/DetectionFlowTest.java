package com.vpssoc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end: agent events -> detection -> correlation -> incidents, against a real Postgres.
 */
@SpringBootTest(properties = {
        "soc.agent-token=test-agent-token-0123456789abcdef",
        "soc.dashboard-token=test-dashboard-token-0123456789ab",
        "soc.detection.trusted-ssh-sources=169.254.0.1"})
@AutoConfigureMockMvc
@Testcontainers
class DetectionFlowTest {

    private static final String AGENT = "Bearer test-agent-token-0123456789abcdef";
    private static final String DASH = "Bearer test-dashboard-token-0123456789ab";

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;

    @Test
    void rejectsRequestsWithoutTheRightToken() throws Exception {
        mvc.perform(post("/api/v1/ingest/events").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        // The dashboard token must not work for ingestion, and vice versa.
        mvc.perform(post("/api/v1/ingest/events").header("Authorization", DASH)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"hostId\":\"x\",\"events\":[]}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/dashboard/summary").header("Authorization", AGENT))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/notifications/telegram/test").header("Authorization", AGENT))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void telegramChannelReportsDisabledWithoutCredentials() throws Exception {
        JsonNode status = getJson("/api/v1/notifications/telegram");
        assertThat(status.get("enabled").asBoolean()).isFalse();
        String res = mvc.perform(post("/api/v1/notifications/telegram/test").header("Authorization", DASH))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(res).get("result").asText()).isEqualTo("DISABLED");
    }

    @Test
    void bruteForceThenLoginThenSudoBecomesOneCorrelatedCriticalIncident() throws Exception {
        String host = "vps-it-1";
        String attacker = "185.220.101.7";
        Instant t0 = Instant.now().minusSeconds(120).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);

        List<Map<String, Object>> batch = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            batch.add(event("SSH_FAILED_LOGIN", t0.plusSeconds(i * 3), attacker, i % 2 == 0 ? "root" : "admin"));
        }
        batch.add(event("SSH_LOGIN_SUCCESS", t0.plusSeconds(60), attacker, "deploy"));
        batch.add(Map.of("type", "SUDO_COMMAND", "occurredAt", t0.plusSeconds(70).toString(), "username", "deploy",
                "metadata", Map.of("command", "/bin/cat /etc/shadow", "runAs", "root")));
        batch.add(Map.of("type", "PORT_OPENED", "occurredAt", t0.plusSeconds(80).toString(), "username", "root",
                "metadata", Map.of("proto", "tcp", "address", "0.0.0.0", "port", 4444, "process", "x", "exe", "/tmp/x", "pid", 999)));
        // Persistence: an SSH key dropped for root, then a shell spawned by the web server.
        batch.add(Map.of("type", "FILE_MODIFIED", "occurredAt", t0.plusSeconds(90).toString(),
                "metadata", Map.of("path", "/root/.ssh/authorized_keys", "oldHash", "aaa", "newHash", "bbb",
                        "size", 742, "owner", "root:root", "mode", "-rw-------", "mtime", t0.plusSeconds(89).toString())));
        batch.add(Map.of("type", "PROCESS_SUSPICIOUS", "occurredAt", t0.plusSeconds(100).toString(), "username", "www-data",
                "metadata", Map.of("reason", "WEB_SHELL", "pid", 4242, "ppid", 900, "comm", "sh", "exe", "/usr/bin/dash",
                        "cmdline", "sh -c id", "parentComm", "php-fpm8.3")));
        batch.add(event("SOMETHING_NEW", t0, null, null)); // unknown types are skipped, not fatal

        JsonNode result = postEvents(host, batch);
        assertThat(result.get("accepted").asInt()).isEqualTo(17);
        assertThat(result.get("skipped").asInt()).isEqualTo(1);

        JsonNode incidents = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        JsonNode bruteForce = byRule(incidents, "SSH_BRUTE_FORCE");
        JsonNode compromise = byRule(incidents, "SSH_LOGIN_AFTER_BRUTE_FORCE");
        JsonNode port = byRule(incidents, "NEW_LISTENING_PORT");

        assertThat(bruteForce.get("sourceIp").asText()).isEqualTo(attacker);
        assertThat(bruteForce.get("eventCount").asInt()).isEqualTo(12);

        assertThat(Instant.parse(compromise.get("firstSeen").asText())).isEqualTo(t0); // first failure, not the login
        assertThat(compromise.get("severity").asText()).isEqualTo("CRITICAL");
        assertThat(compromise.get("riskScore").asInt()).isEqualTo(100);
        assertThat(compromise.findValuesAsText("id")).contains("T1110", "T1078", "T1548.003", "T1571",
                "T1098.004", "T1505.003", "T1059.004");

        assertThat(port.get("severity").asText()).isEqualTo("CRITICAL"); // binary in /tmp

        JsonNode keys = byRule(incidents, "FIM_AUTHORIZED_KEYS", host);
        assertThat(keys.get("severity").asText()).isEqualTo("HIGH");
        assertThat(keys.get("username").asText()).isEqualTo("root");
        assertThat(keys.findValuesAsText("id")).contains("T1098.004");
        JsonNode webShell = byRule(incidents, "WEB_SHELL", host);
        assertThat(webShell.get("severity").asText()).isEqualTo("CRITICAL");
        assertThat(webShell.findValuesAsText("id")).contains("T1505.003", "T1059.004");

        // Timeline of the compromise: the failures, the login, the sudo, the port, the key and the shell.
        JsonNode detail = getJson("/api/v1/incidents/" + compromise.get("id").asLong());
        List<String> types = detail.get("events").findValuesAsText("type");
        assertThat(types).contains("SSH_FAILED_LOGIN", "SSH_LOGIN_SUCCESS", "SUDO_COMMAND", "PORT_OPENED",
                "FILE_MODIFIED", "PROCESS_SUSPICIOUS");

        // A second batch of failures from the same IP is attached to the same incident.
        postEvents(host, List.of(event("SSH_FAILED_LOGIN", t0.plusSeconds(40), attacker, "root")));
        JsonNode again = getJson("/api/v1/incidents/" + bruteForce.get("id").asLong()).get("incident");
        assertThat(again.get("eventCount").asInt()).isEqualTo(13);

        JsonNode summary = getJson("/api/v1/dashboard/summary");
        assertThat(summary.get("securityScore").asInt()).isLessThan(50);
        assertThat(summary.get("attackerIps24h").asInt()).isGreaterThanOrEqualTo(1);

        // Triage: resolve the brute force.
        mvc.perform(patch("/api/v1/incidents/" + bruteForce.get("id").asLong()).header("Authorization", DASH)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"RESOLVED\",\"note\":\"IP bloqueado\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void heartbeatRegistersHostAndRaisesDiskIncident() throws Exception {
        String body = json.writeValueAsString(Map.of(
                "hostId", "vps-it-2", "hostname", "vps", "os", "Ubuntu 24.04", "agentVersion", "test",
                "heartbeatIntervalSeconds", 30,
                "metrics", Map.of("cpuPercent", 12.5, "memPercent", 40.0, "diskPercent", 95.0),
                "openPorts", List.of(Map.of("proto", "tcp", "address", "0.0.0.0", "port", 22))));
        mvc.perform(post("/api/v1/ingest/heartbeat").header("Authorization", AGENT)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isNoContent());

        JsonNode hosts = getJson("/api/v1/hosts");
        assertThat(hosts.findValuesAsText("id")).contains("vps-it-2");
        JsonNode disk = byRule(getJson("/api/v1/incidents?status=OPEN&size=200").get("content"), "DISK_USAGE_HIGH");
        assertThat(disk.get("hostId").asText()).isEqualTo("vps-it-2");
    }

    @Test
    void fileIntegrityAndProcessEventsRaiseTheirOwnIncidents() throws Exception {
        String host = "vps-it-3";
        Instant t = Instant.now().minusSeconds(60).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        String longCron = "/etc/cron.d/" + "x".repeat(300); // longer than the incident key column

        JsonNode result = postEvents(host, List.of(
                Map.of("type", "FILE_BASELINE", "occurredAt", t.toString(),
                        "metadata", Map.of("files", List.of("/etc/passwd", "/etc/ssh/sshd_config"))),
                Map.of("type", "FILE_MODIFIED", "occurredAt", t.toString(),
                        "metadata", Map.of("path", "/etc/ssh/sshd_config", "oldHash", "c1", "newHash", "c2", "size", 3300,
                                "owner", "root:root", "mode", "-rw-r--r--",
                                "addedLines", List.of("PermitRootLogin yes", "X11Forwarding no"),
                                "removedLines", List.of("PermitRootLogin no"))),
                Map.of("type", "FILE_CREATED", "occurredAt", t.plusSeconds(1).toString(),
                        "metadata", Map.of("path", "/etc/cron.d/backdoor", "newHash", "d1", "size", 40,
                                "owner", "root:root", "mode", "-rw-r--r--")),
                Map.of("type", "FILE_CREATED", "occurredAt", t.plusSeconds(2).toString(),
                        "metadata", Map.of("path", longCron, "newHash", "d2", "size", 1, "owner", "root:root", "mode", "-rw-r--r--")),
                Map.of("type", "FILE_MODIFIED", "occurredAt", t.plusSeconds(3).toString(),
                        "metadata", Map.of("path", "/etc/sudoers.d/90-cloud", "oldHash", "e1", "newHash", "e2", "size", 100,
                                "owner", "root:root", "mode", "-rw-rw-rw-", "oldMode", "-r--r-----")),
                Map.of("type", "FILE_MODIFIED", "occurredAt", t.plusSeconds(4).toString(),
                        "metadata", Map.of("path", "/etc/passwd", "oldHash", "f1", "newHash", "f2", "size", 2000,
                                "owner", "root:root", "mode", "-rw-r--r--")),
                Map.of("type", "PROCESS_SUSPICIOUS", "occurredAt", t.plusSeconds(5).toString(), "username", "root",
                        "metadata", Map.of("reason", "DELETED_EXE", "pid", 1, "ppid", 0, "comm", "nginx",
                                "exe", "/usr/sbin/nginx (deleted)", "parentComm", "systemd")),
                Map.of("type", "PROCESS_SUSPICIOUS", "occurredAt", t.plusSeconds(6).toString(), "username", "root",
                        "metadata", Map.of("reason", "DELETED_EXE", "pid", 2, "ppid", 1, "comm", "3",
                                "exe", "/memfd: (deleted)", "parentComm", "bash"))));
        assertThat(result.get("accepted").asInt()).isEqualTo(8);

        JsonNode incidents = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        JsonNode sshd = byRule(incidents, "FIM_SSHD_CONFIG", host);
        assertThat(sshd.get("severity").asText()).isEqualTo("HIGH"); // PermitRootLogin yes was added
        assertThat(sshd.get("description").asText()).contains("PermitRootLogin yes").contains("PermitRootLogin no");
        JsonNode cron = byRule(incidents, "FIM_CRON", host);
        assertThat(cron.get("severity").asText()).isEqualTo("HIGH");
        assertThat(cron.findValuesAsText("id")).contains("T1053.003");
        JsonNode sudoers = byRule(incidents, "FIM_SUDOERS", host);
        assertThat(sudoers.get("severity").asText()).isEqualTo("HIGH");
        assertThat(sudoers.get("description").asText()).contains("gravável por qualquer usuário");
        JsonNode accounts = byRule(incidents, "FIM_ACCOUNTS", host);
        assertThat(accounts.get("severity").asText()).isEqualTo("MEDIUM");
        assertThat(accounts.findValuesAsText("id")).contains("T1136.001", "T1098");

        List<String> processSeverities = new ArrayList<>();
        for (JsonNode n : incidents) {
            if ("SUSPICIOUS_PROCESS".equals(n.get("ruleId").asText()) && host.equals(n.get("hostId").asText())) {
                processSeverities.add(n.get("severity").asText());
            }
        }
        // Upgraded nginx binary is low; a memfd process is fileless malware.
        assertThat(processSeverities).containsExactlyInAnyOrder("LOW", "CRITICAL");
        // No active compromise on this host: nothing is correlated into one.
        for (JsonNode n : incidents) {
            assertThat(host.equals(n.get("hostId").asText()) && "SSH_LOGIN_AFTER_BRUTE_FORCE".equals(n.get("ruleId").asText())).isFalse();
        }

        JsonNode files = getJson("/api/v1/events?category=FILE&hostId=" + host).get("content");
        assertThat(files.findValuesAsText("type")).contains("FILE_BASELINE", "FILE_MODIFIED", "FILE_CREATED")
                .doesNotContain("PROCESS_SUSPICIOUS");
    }

    @Test
    void providerConsoleAccessIsLoggedButNotAnIncident() throws Exception {
        String host = "vps-it-4";
        Instant t = Instant.now().minusSeconds(30).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Map<String, Object> consoleKey = Map.of("type", "ssh-rsa", "bits", 4096, "fingerprint", "SHA256:console",
                "expiresAt", t.plusSeconds(600).toString(), "hasOptions", true);
        Map<String, Object> backdoor = Map.of("type", "ssh-ed25519", "bits", 256, "fingerprint", "SHA256:backdoor",
                "comment", "x@evil", "expiresAt", t.plus(java.time.Duration.ofDays(365)).toString(), "hasOptions", true);

        JsonNode result = postEvents(host, List.of(
                // hPanel terminal: login from the trusted console address + its 10-minute key
                event("SSH_LOGIN_SUCCESS", t, "169.254.0.1", "root"),
                Map.of("type", "FILE_MODIFIED", "occurredAt", t.plusSeconds(5).toString(),
                        "metadata", Map.of("path", "/root/.ssh/authorized_keys", "oldHash", "a", "newHash", "b", "size", 1294,
                                "owner", "root:root", "mode", "-rw-------", "addedKeys", List.of(consoleKey))),
                // ...and the expired key being cleaned up later
                Map.of("type", "FILE_MODIFIED", "occurredAt", t.plusSeconds(20).toString(),
                        "metadata", Map.of("path", "/root/.ssh/authorized_keys", "oldHash", "b", "newHash", "a", "size", 516,
                                "owner", "root:root", "mode", "-rw-------", "removedKeys", List.of(consoleKey))),
                // A long-lived key is a backdoor even if it carries an expiry-time, and still alerts.
                Map.of("type", "FILE_MODIFIED", "occurredAt", t.plusSeconds(25).toString(),
                        "metadata", Map.of("path", "/home/deploy/.ssh/authorized_keys", "oldHash", "c", "newHash", "d", "size", 300,
                                "owner", "deploy:deploy", "mode", "-rw-------", "addedKeys", List.of(backdoor))),
                event("SSH_LOGIN_SUCCESS", t.plusSeconds(28), "203.0.113.200", "root")));
        assertThat(result.get("accepted").asInt()).isEqualTo(5);

        JsonNode incidents = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        List<String> keyPaths = new ArrayList<>();
        List<String> rootLoginIps = new ArrayList<>();
        for (JsonNode n : incidents) {
            if (!host.equals(n.get("hostId").asText())) continue;
            if ("FIM_AUTHORIZED_KEYS".equals(n.get("ruleId").asText())) keyPaths.add(n.get("title").asText());
            if ("SSH_ROOT_LOGIN".equals(n.get("ruleId").asText())) rootLoginIps.add(n.get("sourceIp").asText());
        }
        assertThat(keyPaths).hasSize(1).allMatch(s -> s.contains("/home/deploy/.ssh/authorized_keys"));
        assertThat(rootLoginIps).containsExactly("203.0.113.200");

        JsonNode deployKeys = byRule(incidents, "FIM_AUTHORIZED_KEYS", host);
        assertThat(deployKeys.get("severity").asText()).isEqualTo("HIGH");
        assertThat(deployKeys.get("description").asText()).contains("SHA256:backdoor").contains("x@evil");

        // The console activity is still in the event log.
        JsonNode logged = getJson("/api/v1/events?hostId=" + host + "&size=50").get("content");
        assertThat(logged.findValuesAsText("type")).contains("SSH_LOGIN_SUCCESS", "FILE_MODIFIED");
    }

    private Map<String, Object> event(String type, Instant at, String ip, String user) {
        Map<String, Object> m = new java.util.HashMap<>();
        m.put("type", type);
        m.put("occurredAt", at.toString());
        if (ip != null) m.put("sourceIp", ip);
        if (user != null) m.put("username", user);
        m.put("metadata", Map.of("method", "password"));
        return m;
    }

    private JsonNode postEvents(String host, List<Map<String, Object>> events) throws Exception {
        String body = json.writeValueAsString(Map.of("hostId", host, "events", events));
        String res = mvc.perform(post("/api/v1/ingest/events").header("Authorization", AGENT)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(res);
    }

    private JsonNode getJson(String url) throws Exception {
        String res = mvc.perform(get(url).header("Authorization", DASH))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(res);
    }

    private static JsonNode byRule(JsonNode incidents, String ruleId) {
        return byRule(incidents, ruleId, null);
    }

    private static JsonNode byRule(JsonNode incidents, String ruleId, String hostId) {
        for (JsonNode n : incidents) {
            if (ruleId.equals(n.get("ruleId").asText()) && (hostId == null || hostId.equals(n.get("hostId").asText()))) {
                return n;
            }
        }
        throw new AssertionError("no incident for rule " + ruleId + " in " + incidents);
    }
}
