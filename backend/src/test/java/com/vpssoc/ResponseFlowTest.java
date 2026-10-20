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
import org.springframework.test.web.servlet.ResultMatcher;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Active response end to end: playbooks queue actions, the agent polls and reports, the SOC
 * records blocks and contains incidents; plus posture findings, explanations and KPIs.
 */
@SpringBootTest(properties = {
        "soc.agent-token=test-agent-token-0123456789abcdef",
        "soc.dashboard-token=test-dashboard-token-0123456789ab",
        "soc.detection.trusted-ssh-sources=169.254.0.1"})
@AutoConfigureMockMvc
@Testcontainers
class ResponseFlowTest {

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
    void bruteForceIsBlockedAutomaticallyAndTheIncidentClosesItself() throws Exception {
        String host = "vps-resp-1";
        String attacker = "45.155.205.10";
        Instant t0 = Instant.now().minusSeconds(90).truncatedTo(ChronoUnit.MILLIS);
        List<Map<String, Object>> batch = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            batch.add(event("SSH_INVALID_USER", t0.plusSeconds(i * 2), attacker, List.of("admin", "oracle", "test").get(i % 3)));
        }
        postEvents(host, batch);

        JsonNode brute = byRule(getJson("/api/v1/incidents?status=OPEN").get("content"), "SSH_BRUTE_FORCE", host);
        long incidentId = brute.get("id").asLong();

        // The playbook queued an automatic block; the agent picks it up on its next poll.
        JsonNode orders = agentPoll(host).get("actions");
        assertThat(orders).hasSize(1);
        JsonNode order = orders.get(0);
        assertThat(order.get("type").asText()).isEqualTo("BLOCK_IP");
        assertThat(order.get("params").get("ip").asText()).isEqualTo(attacker);
        assertThat(order.get("params").get("ttlSeconds").asLong()).isEqualTo(86_400);
        assertThat(agentPoll(host).get("actions")).isEmpty(); // dispatched once

        // Another host's agent cannot report it.
        report(order.get("id").asLong(), "someone-else", "SUCCEEDED", "x", Map.of(), status().isBadRequest());
        String until = Instant.now().plusSeconds(86_400).toString();
        report(order.get("id").asLong(), host, "SUCCEEDED", attacker + " bloqueado", Map.of("ip", attacker, "until", until), status().isNoContent());

        JsonNode detail = getJson("/api/v1/incidents/" + incidentId);
        JsonNode inc = detail.get("incident");
        assertThat(inc.get("status").asText()).isEqualTo("RESOLVED");
        assertThat(inc.get("containedAt").isNull()).isFalse();
        assertThat(inc.get("resolutionNote").asText()).contains("Contido automaticamente").contains(attacker);

        JsonNode blocks = getJson("/api/v1/response/blocks");
        assertThat(blocks.findValuesAsText("ip")).contains(attacker);

        // The explanation tells the story with the real numbers and concrete next steps.
        JsonNode ex = detail.get("explanation");
        assertThat(ex.get("summary").asText()).contains(attacker).contains("12 tentativas").contains("admin");
        assertThat(ex.get("impact").asText()).isNotBlank();
        assertThat(ex.get("response").asText()).contains("Bloquear IP " + attacker).contains("automaticamente");
        assertThat(ex.get("recommendations").findValuesAsText("command")).anyMatch(c -> c.contains("nft list set inet vps_soc"));
        assertThat(ex.get("falsePositive").asText()).contains("nunca fez login");
        assertThat(detail.get("ip").get("failures").asLong()).isEqualTo(12);
        assertThat(detail.get("ip").get("kind").asText()).isEqualTo("PUBLIC");
        assertThat(detail.get("actions").get(0).get("status").asText()).isEqualTo("SUCCEEDED");

        // Manual unblock goes through the agent too.
        long blockId = blocks.get(0).get("id").asLong();
        JsonNode unblock = postJson("/api/v1/response/blocks/" + blockId + "/unblock", Map.of());
        assertThat(unblock.get("type").asText()).isEqualTo("UNBLOCK_IP");
        JsonNode next = agentPoll(host).get("actions").get(0);
        report(next.get("id").asLong(), host, "SUCCEEDED", "desbloqueado", Map.of(), status().isNoContent());
        assertThat(getJson("/api/v1/response/blocks").findValuesAsText("ip")).doesNotContain(attacker);
    }

    @Test
    void compromiseStretchesTheBlockAndTheIncidentShowsIt() throws Exception {
        String host = "vps-resp-5";
        String attacker = "91.92.93.94";
        Instant t0 = Instant.now().minusSeconds(120);
        List<Map<String, Object>> batch = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            batch.add(event("SSH_FAILED_LOGIN", t0.plusSeconds(i), attacker, "deploy"));
        }
        batch.add(event("SSH_LOGIN_SUCCESS", t0.plusSeconds(20), attacker, "deploy"));
        postEvents(host, batch);

        // One block, queued by the brute force, upgraded to the compromise duration (7 days).
        JsonNode orders = agentPoll(host).get("actions");
        assertThat(orders).hasSize(1);
        assertThat(orders.get(0).get("params").get("ttlSeconds").asLong()).isEqualTo(7 * 86_400);
        report(orders.get(0).get("id").asLong(), host, "SUCCEEDED", "bloqueado", Map.of("until", Instant.now().plusSeconds(7 * 86_400).toString()), status().isNoContent());

        JsonNode compromise = byRule(getJson("/api/v1/incidents?status=OPEN&size=200").get("content"), "SSH_LOGIN_AFTER_BRUTE_FORCE", host);
        assertThat(compromise.get("containedAt").isNull()).isFalse();
        JsonNode detail = getJson("/api/v1/incidents/" + compromise.get("id").asLong());
        assertThat(detail.get("actions").findValuesAsText("type")).contains("BLOCK_IP"); // the sibling's block is shown here too
        assertThat(detail.get("explanation").get("recommendations").findValuesAsText("command")).anyMatch(c -> c.contains("pkill -KILL -u deploy"));
    }

    @Test
    void ownersKnownIpOnlyGetsABlockProposalAndProtectedRangesNone() throws Exception {
        String host = "vps-resp-2";
        String owner = "203.0.113.77";
        Instant t0 = Instant.now().minusSeconds(3600);
        List<Map<String, Object>> batch = new ArrayList<>();
        batch.add(event("SSH_LOGIN_SUCCESS", t0, owner, "thiago"));
        for (int i = 0; i < 11; i++) {
            batch.add(event("SSH_FAILED_LOGIN", Instant.now().minusSeconds(40 - i), owner, "thiago"));
        }
        // Tailscale range: never blocked, whatever happens.
        for (int i = 0; i < 11; i++) {
            batch.add(event("SSH_FAILED_LOGIN", Instant.now().minusSeconds(30 - i), "100.90.1.2", "root"));
        }
        postEvents(host, batch);

        JsonNode actions = getJson("/api/v1/response/actions?size=200").get("content");
        JsonNode proposal = null;
        for (JsonNode a : actions) {
            if (host.equals(a.get("hostId").asText())) {
                assertThat(a.get("target").asText()).isNotEqualTo("100.90.1.2");
                if (owner.equals(a.get("target").asText())) proposal = a;
            }
        }
        assertThat(proposal).isNotNull();
        assertThat(proposal.get("status").asText()).isEqualTo("PROPOSED");
        assertThat(proposal.get("reason").asText()).contains("já fez login com sucesso");
        assertThat(agentPoll(host).get("actions")).isEmpty(); // nothing runs without approval

        JsonNode incidents = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        JsonNode tailscale = null;
        for (JsonNode n : incidents) {
            if (host.equals(n.get("hostId").asText()) && "100.90.1.2".equals(n.path("sourceIp").asText())) tailscale = n;
        }
        assertThat(tailscale).isNotNull();
        JsonNode ex = getJson("/api/v1/incidents/" + tailscale.get("id").asLong()).get("explanation");
        assertThat(ex.get("response").asText()).contains("faixa protegida");

        // Approve → the agent gets it.
        postJson("/api/v1/response/actions/" + proposal.get("id").asLong() + "/approve", Map.of());
        assertThat(agentPoll(host).get("actions").findValuesAsText("type")).containsExactly("BLOCK_IP");
    }

    @Test
    void agentLocalBlockIsRecordedAndContainsTheIncident() throws Exception {
        String host = "vps-resp-3";
        String attacker = "80.94.95.11";
        List<Map<String, Object>> batch = new ArrayList<>();
        Instant t0 = Instant.now().minusSeconds(60);
        for (int i = 0; i < 10; i++) {
            batch.add(event("SSH_FAILED_LOGIN", t0.plusSeconds(i), attacker, "root"));
        }
        // While the SOC was offline the agent's guard already blocked the IP.
        Map<String, Object> local = new HashMap<>();
        local.put("type", "RESPONSE_EXECUTED");
        local.put("occurredAt", t0.plusSeconds(11).toString());
        local.put("sourceIp", attacker);
        local.put("message", attacker + " bloqueado automaticamente pelo agente");
        local.put("metadata", Map.of("action", "BLOCK_IP", "origin", "agent", "status", "SUCCEEDED", "reason", "10 falhas de login SSH em 2m0s",
                "ttlSeconds", 86400, "until", Instant.now().plusSeconds(86_000).toString()));
        batch.add(local);
        // Lines that were still in flight when the block landed must not open new incidents.
        for (int i = 0; i < 5; i++) {
            batch.add(event("SSH_FAILED_LOGIN", t0.plusSeconds(12 + i), attacker, "root"));
        }
        postEvents(host, batch);

        long bruteForceIncidents = 0;
        for (JsonNode n : getJson("/api/v1/incidents?size=200").get("content")) {
            if (host.equals(n.get("hostId").asText()) && "SSH_BRUTE_FORCE".equals(n.get("ruleId").asText())) bruteForceIncidents++;
        }
        assertThat(bruteForceIncidents).isEqualTo(1);

        JsonNode closed = byRule(getJson("/api/v1/incidents?status=RESOLVED&size=200").get("content"), "SSH_BRUTE_FORCE", host);
        assertThat(closed.get("containmentNote").asText()).contains("pelo agente");
        assertThat(agentPoll(host).get("actions")).isEmpty(); // no duplicate block from the SOC
        JsonNode actions = getJson("/api/v1/response/actions?size=200").get("content");
        boolean found = false;
        for (JsonNode a : actions) {
            if (host.equals(a.get("hostId").asText()) && "AGENT".equals(a.get("origin").asText())) found = true;
        }
        assertThat(found).isTrue();
    }

    @Test
    void postureFindingsOpenResolveAndCanBeAcceptedAsRisk() throws Exception {
        String host = "vps-resp-4";
        heartbeat(host, Map.of("failedUnits", List.of("nginx.service"), "pendingUpdates", 12, "securityUpdates", 5,
                "rebootRequired", true, "ssh", Map.of("passwordAuthentication", "yes", "permitRootLogin", "without-password"),
                "sessions", List.of(), "firewall", Map.of("enabled", true, "blockedIps", 2, "droppedPackets", 340)));

        JsonNode open = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        JsonNode svc = byRule(open, "SERVICE_FAILED", host);
        byRule(open, "SECURITY_UPDATES", host);
        byRule(open, "REBOOT_REQUIRED", host);
        JsonNode ssh = byRule(open, "SSH_WEAK_CONFIG", host);
        JsonNode svcDetail = getJson("/api/v1/incidents/" + svc.get("id").asLong());
        assertThat(svcDetail.get("actions").get(0).get("type").asText()).isEqualTo("RESTART_SERVICE");
        assertThat(svcDetail.get("actions").get(0).get("status").asText()).isEqualTo("PROPOSED");
        assertThat(getJson("/api/v1/incidents/" + ssh.get("id").asLong()).get("explanation").get("recommendations")
                .findValuesAsText("command")).anyMatch(c -> c.contains("PasswordAuthentication no"));

        // Operator accepts the SSH finding as a risk.
        mvc.perform(patch("/api/v1/incidents/" + ssh.get("id").asLong()).header("Authorization", DASH)
                .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"FALSE_POSITIVE\",\"note\":\"preciso de senha\"}"))
                .andExpect(status().isOk());

        // Everything fixed except SSH (still weak, but accepted).
        heartbeat(host, Map.of("failedUnits", List.of(), "pendingUpdates", 0, "securityUpdates", 0, "rebootRequired", false,
                "ssh", Map.of("passwordAuthentication", "yes", "permitRootLogin", "without-password"), "sessions", List.of()));
        JsonNode after = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        for (JsonNode n : after) {
            assertThat(host.equals(n.get("hostId").asText())).as("no open finding left for %s: %s", host, n.get("ruleId")).isFalse();
        }

        JsonNode kpis = getJson("/api/v1/dashboard/kpis?days=30");
        assertThat(kpis.get("incidentsOpened").asLong()).isGreaterThanOrEqualTo(4);
        assertThat(kpis.get("falsePositives").asLong()).isGreaterThanOrEqualTo(1);
        assertThat(kpis.get("mttdSeconds").isNull()).isFalse();
        assertThat(kpis.get("daily")).isNotEmpty();
        assertThat(kpis.get("actionsAwaitingApproval").asLong()).isGreaterThanOrEqualTo(1);
    }

    // ---------------------------------------------------------------- helpers

    private void heartbeat(String host, Map<String, Object> posture) throws Exception {
        String body = json.writeValueAsString(Map.of("hostId", host, "hostname", host, "os", "Ubuntu 24.04", "agentVersion", "test",
                "heartbeatIntervalSeconds", 30,
                "metrics", Map.of("cpuPercent", 5.0, "memPercent", 30.0, "diskPercent", 40.0, "netRxBps", 1200.5, "tcpEstablished", 7),
                "openPorts", List.of(), "posture", posture, "response", Map.of("enabled", true, "autoBlock", true)));
        mvc.perform(post("/api/v1/ingest/heartbeat").header("Authorization", AGENT)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isNoContent());
    }

    private JsonNode agentPoll(String host) throws Exception {
        String res = mvc.perform(post("/api/v1/ingest/actions/poll").header("Authorization", AGENT)
                        .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("hostId", host))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(res);
    }

    private void report(long id, String host, String status, String output, Map<String, Object> details, ResultMatcher expect) throws Exception {
        mvc.perform(post("/api/v1/ingest/actions/" + id + "/result").header("Authorization", AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("hostId", host, "status", status, "output", output, "details", details))))
                .andExpect(expect);
    }

    private Map<String, Object> event(String type, Instant at, String ip, String user) {
        Map<String, Object> m = new HashMap<>();
        m.put("type", type);
        m.put("occurredAt", at.toString());
        if (ip != null) m.put("sourceIp", ip);
        if (user != null) m.put("username", user);
        m.put("metadata", Map.of("method", "password"));
        return m;
    }

    private void postEvents(String host, List<Map<String, Object>> events) throws Exception {
        mvc.perform(post("/api/v1/ingest/events").header("Authorization", AGENT)
                        .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("hostId", host, "events", events))))
                .andExpect(status().isOk());
    }

    private JsonNode postJson(String url, Object body) throws Exception {
        String res = mvc.perform(post(url).header("Authorization", DASH)
                        .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(res);
    }

    private JsonNode getJson(String url) throws Exception {
        String res = mvc.perform(get(url).header("Authorization", DASH))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(res);
    }

    private static JsonNode byRule(JsonNode incidents, String ruleId, String hostId) {
        for (JsonNode n : incidents) {
            if (ruleId.equals(n.get("ruleId").asText()) && hostId.equals(n.get("hostId").asText())) {
                return n;
            }
        }
        throw new AssertionError("no incident for rule " + ruleId + " on " + hostId + " in " + incidents);
    }
}
