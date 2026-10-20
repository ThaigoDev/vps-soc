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
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** PM2 apps: health, incidents, attribution of port incidents, restart action. */
@SpringBootTest(properties = {
        "soc.agent-token=test-agent-token-0123456789abcdef",
        "soc.dashboard-token=test-dashboard-token-0123456789ab"})
@AutoConfigureMockMvc
@Testcontainers
class ServiceFlowTest {

    private static final String AGENT = "Bearer test-agent-token-0123456789abcdef";
    private static final String DASH = "Bearer test-dashboard-token-0123456789ab";
    private static final long GB = 1L << 30;

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;

    @Test
    void pm2AppsGetHealthIncidentsAndRestart() throws Exception {
        String host = "vps-svc-1";
        heartbeat(host, List.of(
                app("api", 0, 1001, "online", 0, 120L << 20, List.of(3000)),
                app("worker", 1, 0, "errored", 15, 0L, List.of()),
                app("hungry", 2, 1003, "online", 0, 2 * GB, List.of())));

        JsonNode open = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        JsonNode down = byRule(open, "SERVICE_DOWN", host);
        assertThat(down.get("service").asText()).isEqualTo("worker");
        assertThat(down.get("severity").asText()).isEqualTo("HIGH");
        JsonNode mem = byRule(open, "SERVICE_HIGH_MEMORY", host);
        assertThat(mem.get("service").asText()).isEqualTo("hungry"); // 2 GB of 4 GB = 50% > 40%

        // The crash opened a restart proposal for the agent (approval by default).
        JsonNode downDetail = getJson("/api/v1/incidents/" + down.get("id").asLong());
        JsonNode action = downDetail.get("actions").get(0);
        assertThat(action.get("type").asText()).isEqualTo("PM2_RESTART");
        assertThat(action.get("status").asText()).isEqualTo("PROPOSED");
        assertThat(action.get("params").get("pmId").asInt()).isEqualTo(1);
        assertThat(downDetail.get("explanation").get("recommendations").findValuesAsText("command"))
                .anyMatch(c -> c.contains("pm2 logs worker"));

        // Restarts piling up raise a crash loop, with the error log as evidence.
        Instant now = Instant.now();
        postEvents(host, List.of(
                restarted("api", 2, now.minusSeconds(120)),
                restarted("api", 2, now.minusSeconds(30))));
        JsonNode loop = byRule(getJson("/api/v1/incidents?status=OPEN&size=200").get("content"), "SERVICE_CRASH_LOOP", host);
        assertThat(loop.get("service").asText()).isEqualTo("api");
        JsonNode loopEx = getJson("/api/v1/incidents/" + loop.get("id").asLong()).get("explanation");
        assertThat(loopEx.get("evidence").findValuesAsText("value")).anyMatch(v -> v.contains("Error: ECONNREFUSED"));

        // A port opened by the app's process is attributed to the app.
        Map<String, Object> port = new HashMap<>();
        port.put("type", "PORT_OPENED");
        port.put("occurredAt", now.toString());
        port.put("metadata", Map.of("proto", "tcp", "address", "0.0.0.0", "port", 3001, "process", "node", "pid", 1001, "exe", "/usr/bin/node"));
        postEvents(host, List.of(port));
        JsonNode portInc = byRule(getJson("/api/v1/incidents?status=OPEN&size=200").get("content"), "NEW_LISTENING_PORT", host);
        assertThat(portInc.get("service").asText()).isEqualTo("api");

        // The services view: pm2 list + health verdict + incidents per app.
        Map<String, JsonNode> svc = new HashMap<>();
        for (JsonNode s : getJson("/api/v1/services")) {
            if (host.equals(s.get("hostId").asText())) svc.put(s.get("pm2").get("name").asText(), s);
        }
        assertThat(svc.get("worker").get("health").asText()).isEqualTo("DOWN");
        assertThat(svc.get("api").get("health").asText()).isEqualTo("DEGRADED");
        assertThat(svc.get("api").get("reasons").toString()).contains("crash loop");
        assertThat(svc.get("api").get("activeIncidents").size()).isGreaterThanOrEqualTo(2);
        assertThat(svc.get("api").get("pm2").get("ports").get(0).asInt()).isEqualTo(3000);
        assertThat(svc.get("hungry").get("health").asText()).isEqualTo("DEGRADED");

        JsonNode detail = getJson("/api/v1/services/" + host + "/api");
        assertThat(detail.get("samples")).isNotEmpty();
        assertThat(detail.get("events").findValuesAsText("type")).contains("SERVICE_RESTARTED");

        // Manual restart from the dashboard goes straight to the agent queue.
        String res = mvc.perform(post("/api/v1/services/" + host + "/api/restart").header("Authorization", DASH))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(res).get("status").asText()).isEqualTo("PENDING");
        JsonNode orders = agentPoll(host).get("actions");
        assertThat(orders.findValuesAsText("type")).contains("PM2_RESTART");

        // Worker comes back and memory drops: their incidents close themselves.
        heartbeat(host, List.of(
                app("api", 0, 1001, "online", 4, 120L << 20, List.of(3000)),
                app("worker", 1, 1002, "online", 16, 80L << 20, List.of()),
                app("hungry", 2, 1003, "online", 0, 300L << 20, List.of())));
        JsonNode after = getJson("/api/v1/incidents?status=OPEN&size=200").get("content");
        for (JsonNode n : after) {
            if (host.equals(n.get("hostId").asText())) {
                assertThat(n.get("ruleId").asText()).isNotIn("SERVICE_DOWN", "SERVICE_HIGH_MEMORY");
            }
        }
    }

    @Test
    void deliberateStopCanBeAcceptedAndStaysQuiet() throws Exception {
        String host = "vps-svc-2";
        heartbeat(host, List.of(app("cron-job", 0, 0, "stopped", 0, 0L, List.of())));
        JsonNode down = byRule(getJson("/api/v1/incidents?status=OPEN&size=200").get("content"), "SERVICE_DOWN", host);
        assertThat(down.get("severity").asText()).isEqualTo("MEDIUM");
        assertThat(getJson("/api/v1/incidents/" + down.get("id").asLong()).get("actions")).isEmpty(); // no restart for a stop

        mvc.perform(patch("/api/v1/incidents/" + down.get("id").asLong()).header("Authorization", DASH)
                .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"FALSE_POSITIVE\",\"note\":\"parado de propósito\"}"))
                .andExpect(status().isOk());
        heartbeat(host, List.of(app("cron-job", 0, 0, "stopped", 0, 0L, List.of())));
        for (JsonNode n : getJson("/api/v1/incidents?status=OPEN&size=200").get("content")) {
            assertThat(host.equals(n.get("hostId").asText())).isFalse();
        }
    }

    // ---------------------------------------------------------------- helpers

    private Map<String, Object> app(String name, int pmId, int pid, String status, int restarts, long mem, List<Integer> ports) {
        Map<String, Object> m = new HashMap<>();
        m.put("source", "pm2");
        m.put("name", name);
        m.put("pmId", pmId);
        m.put("pid", pid);
        m.put("status", status);
        m.put("restarts", restarts);
        m.put("unstableRestarts", 0);
        m.put("cpuPercent", 2.5);
        m.put("memoryBytes", mem);
        m.put("mode", "fork");
        m.put("execPath", "/home/proj/" + name + "/index.js");
        m.put("user", "deploy");
        m.put("pm2Home", "/home/deploy/.pm2");
        m.put("ports", ports);
        return m;
    }

    private Map<String, Object> restarted(String name, int delta, Instant at) {
        Map<String, Object> e = new HashMap<>();
        e.put("type", "SERVICE_RESTARTED");
        e.put("occurredAt", at.toString());
        e.put("username", "deploy");
        e.put("metadata", Map.of("service", name, "source", "pm2", "pmId", 0, "delta", delta, "restarts", 10,
                "status", "online", "errLogTail", List.of("Error: ECONNREFUSED 127.0.0.1:5432", "    at TCPConnectWrap.afterConnect")));
        return e;
    }

    private void heartbeat(String host, List<Map<String, Object>> services) throws Exception {
        String body = json.writeValueAsString(Map.of("hostId", host, "hostname", host, "os", "Ubuntu 24.04", "agentVersion", "test",
                "heartbeatIntervalSeconds", 30,
                "metrics", Map.of("cpuPercent", 5.0, "memPercent", 30.0, "memTotalBytes", 4 * GB, "diskPercent", 40.0),
                "openPorts", List.of(), "services", services, "pm2", Map.of("daemons", List.of("/home/deploy/.pm2 (deploy, 5.4.3)"))));
        mvc.perform(post("/api/v1/ingest/heartbeat").header("Authorization", AGENT)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isNoContent());
    }

    private void postEvents(String host, List<Map<String, Object>> events) throws Exception {
        mvc.perform(post("/api/v1/ingest/events").header("Authorization", AGENT)
                        .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("hostId", host, "events", events))))
                .andExpect(status().isOk());
    }

    private JsonNode agentPoll(String host) throws Exception {
        String res = mvc.perform(post("/api/v1/ingest/actions/poll").header("Authorization", AGENT)
                        .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("hostId", host))))
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
