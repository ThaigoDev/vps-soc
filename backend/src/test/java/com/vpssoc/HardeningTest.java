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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Slow brute force, per-host agent tokens and the lockout of addresses guessing tokens. */
@SpringBootTest(properties = {
        "soc.agent-token=test-agent-token-0123456789abcdef",
        "soc.dashboard-token=test-dashboard-token-0123456789ab",
        "soc.agent-host-tokens=web-a=host-a-token-0123456789abcdef, web-b = host-b-token-0123456789abcdef"})
@AutoConfigureMockMvc
@Testcontainers
class HardeningTest {

    private static final String AGENT = "Bearer test-agent-token-0123456789abcdef";
    private static final String DASH = "Bearer test-dashboard-token-0123456789ab";
    private static final String HOST_A = "Bearer host-a-token-0123456789abcdef";

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;

    @Test
    void slowBruteForceUnderTheShortWindowStillOpensAnIncident() throws Exception {
        String host = "vps-slow";
        String attacker = "45.95.147.10";
        Instant t0 = Instant.now().minus(55, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS);
        List<Map<String, Object>> batch = new ArrayList<>();
        for (int i = 0; i < 19; i++) { // one attempt every 2.5 min: never 2 inside the 60 s window
            batch.add(failure(t0.plusSeconds(i * 150L), attacker));
        }
        postEvents(AGENT, host, batch, 200);
        assertThat(incidents(host)).isEmpty(); // 19 < 20 per hour

        postEvents(AGENT, host, List.of(failure(t0.plusSeconds(19 * 150L), attacker)), 200);
        List<JsonNode> open = incidents(host);
        assertThat(open).hasSize(1);
        JsonNode inc = open.get(0);
        assertThat(inc.get("ruleId").asText()).isEqualTo("SSH_BRUTE_FORCE");
        assertThat(inc.get("title").asText()).contains("lento");
        assertThat(inc.get("sourceIp").asText()).isEqualTo(attacker);
        assertThat(inc.get("eventCount").asInt()).isEqualTo(20);

        // More attempts are attached to it, not a second incident, and the title stays.
        postEvents(AGENT, host, List.of(failure(t0.plusSeconds(20 * 150L), attacker)), 200);
        assertThat(incidents(host)).hasSize(1);
        assertThat(incidents(host).get(0).get("eventCount").asInt()).isEqualTo(21);
    }

    @Test
    void aHostTokenOnlySpeaksForItsOwnHost() throws Exception {
        postEvents(HOST_A, "web-a", List.of(failure(Instant.now(), "203.0.113.1")), 200);
        postEvents(HOST_A, "web-b", List.of(failure(Instant.now(), "203.0.113.1")), 403);
        mvc.perform(post("/api/v1/ingest/actions/poll").header("Authorization", HOST_A)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"hostId\":\"web-b\"}"))
                .andExpect(status().isForbidden());
        // The shared token keeps working for any host (existing installs are unaffected).
        postEvents(AGENT, "web-b", List.of(failure(Instant.now(), "203.0.113.1")), 200);
        // A host token is not a dashboard token.
        mvc.perform(get("/api/v1/hosts").header("Authorization", HOST_A)).andExpect(status().isUnauthorized());
    }

    @Test
    void anAddressGuessingTokensIsLockedOut() throws Exception {
        String guesser = "198.51.100.77";
        for (int i = 0; i < 10; i++) {
            mvc.perform(from(get("/api/v1/hosts").header("Authorization", "Bearer guess-" + i), guesser))
                    .andExpect(status().isUnauthorized());
        }
        // Locked: not even the right token is checked from that address now.
        mvc.perform(from(get("/api/v1/hosts").header("Authorization", DASH), guesser))
                .andExpect(status().isTooManyRequests());
        // Other addresses, and the agent endpoints, are not affected.
        mvc.perform(from(get("/api/v1/hosts").header("Authorization", DASH), "198.51.100.78"))
                .andExpect(status().isOk());
        mvc.perform(from(post("/api/v1/ingest/actions/poll").header("Authorization", AGENT)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"hostId\":\"vps-x\"}"), guesser))
                .andExpect(status().isOk());
    }

    @Test
    void webScannersAreEventsButExploitAttemptsOpenAnIncidentWithABlockProposal() throws Exception {
        String host = "vps-web";
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        // Background noise: someone looking for /.env and /wp-login.php. Logged, no incident.
        postEvents(AGENT, host, List.of(web(now.minusSeconds(60), "64.62.197.9", 40, 0, Map.of("SENSITIVE_FILE", 25, "ADMIN_PROBE", 15), "")), 200);
        assertThat(incidents(host)).isEmpty();

        // Two SQL injection attempts: still below the bar.
        String attacker = "103.77.10.5";
        postEvents(AGENT, host, List.of(web(now.minusSeconds(30), attacker, 2, 2, Map.of("SQLI", 2), "")), 200);
        assertThat(incidents(host)).isEmpty();
        // The third one opens the incident.
        postEvents(AGENT, host, List.of(web(now.minusSeconds(20), attacker, 1, 1, Map.of("PATH_TRAVERSAL", 1), "")), 200);
        List<JsonNode> open = incidents(host);
        assertThat(open).hasSize(1);
        JsonNode inc = open.get(0);
        assertThat(inc.get("ruleId").asText()).isEqualTo("WEB_ATTACK");
        assertThat(inc.get("severity").asText()).isEqualTo("MEDIUM");
        assertThat(inc.get("sourceIp").asText()).isEqualTo(attacker);
        assertThat(inc.get("eventCount").asInt()).isEqualTo(2);
        assertThat(inc.findValuesAsText("id")).contains("T1190", "T1595.002");
        assertThat(inc.get("title").asText()).contains("SQL injection", "path traversal");

        // Blocking is proposed (APPROVAL by default), never automatic.
        String actions = mvc.perform(get("/api/v1/response/actions?size=50").header("Authorization", DASH))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        boolean proposed = false;
        for (JsonNode a : json.readTree(actions).get("content")) {
            if ("BLOCK_IP".equals(a.get("type").asText()) && a.toString().contains(attacker)) {
                assertThat(a.get("status").asText()).isEqualTo("PROPOSED");
                proposed = true;
            }
        }
        assertThat(proposed).isTrue();

        // An attack tool alone (nikto) is enough; the explanation renders.
        postEvents(AGENT, host, List.of(web(now.minusSeconds(10), "5.188.62.140", 6, 0, Map.of("ADMIN_PROBE", 6), "nikto")), 200);
        assertThat(incidents(host)).hasSize(2);
        mvc.perform(get("/api/v1/incidents/" + inc.get("id").asLong()).header("Authorization", DASH)).andExpect(status().isOk());
    }

    private static Map<String, Object> web(Instant at, String ip, int requests, int exploits, Map<String, Integer> categories, String tool) {
        Map<String, Object> m = new HashMap<>();
        m.put("type", "WEB_ATTACK");
        m.put("occurredAt", at.toString());
        m.put("sourceIp", ip);
        m.put("metadata", Map.of("requests", requests, "exploitRequests", exploits, "categories", categories,
                "statuses", Map.of("404", requests), "successfulRequests", 0, "tool", tool,
                "samples", List.of("GET /x?id=1' or '1'='1 → 404"), "userAgent", "Mozilla/5.0"));
        return m;
    }

    private static MockHttpServletRequestBuilder from(MockHttpServletRequestBuilder b, String ip) {
        return b.with(r -> {
            r.setRemoteAddr(ip);
            return r;
        });
    }

    private static Map<String, Object> failure(Instant at, String ip) {
        Map<String, Object> m = new HashMap<>();
        m.put("type", "SSH_FAILED_LOGIN");
        m.put("occurredAt", at.toString());
        m.put("sourceIp", ip);
        m.put("username", "root");
        m.put("metadata", Map.of("method", "password"));
        return m;
    }

    private void postEvents(String auth, String host, List<Map<String, Object>> events, int expected) throws Exception {
        mvc.perform(post("/api/v1/ingest/events").header("Authorization", auth).contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("hostId", host, "events", events))))
                .andExpect(status().is(expected));
    }

    private List<JsonNode> incidents(String host) throws Exception {
        String res = mvc.perform(get("/api/v1/incidents?status=OPEN&size=200").header("Authorization", DASH))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        List<JsonNode> out = new ArrayList<>();
        json.readTree(res).get("content").forEach(n -> {
            if (host.equals(n.get("hostId").asText())) {
                out.add(n);
            }
        });
        return out;
    }
}
