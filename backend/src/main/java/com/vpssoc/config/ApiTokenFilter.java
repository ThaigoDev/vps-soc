package com.vpssoc.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bearer-token auth for the API: agents use {@code soc.agent-token} (or a per-host token from
 * {@code soc.agent-host-tokens}) on /api/v1/ingest/**, the dashboard uses
 * {@code soc.dashboard-token} on everything else under /api.
 *
 * <p>An address that sends {@value #MAX_FAILURES} wrong tokens within {@link #FAILURE_WINDOW}
 * is refused (429) for {@link #LOCKOUT} without even checking the token, so a token cannot be
 * guessed online.
 */
@Component
public class ApiTokenFilter extends OncePerRequestFilter {

    /** Request attribute set when a per-host token authenticated the request: the host id it is bound to. */
    public static final String AGENT_HOST_ATTR = "soc.agentHost";

    static final int MAX_FAILURES = 10;
    static final Duration FAILURE_WINDOW = Duration.ofMinutes(10);
    static final Duration LOCKOUT = Duration.ofMinutes(15);

    private static final Logger log = LoggerFactory.getLogger(ApiTokenFilter.class);
    private static final String INGEST_PREFIX = "/api/v1/ingest/";

    private final SocProperties props;
    private final Clock clock;
    private final Map<String, String> hostTokens;
    private final Map<String, Deque<Instant>> failures = new ConcurrentHashMap<>();
    private final Map<String, Instant> lockedUntil = new ConcurrentHashMap<>();

    public ApiTokenFilter(SocProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
        this.hostTokens = parseHostTokens(props.agentHostTokens());
    }

    /** "host=token,host2=token2" → host → token (blank entries ignored). */
    static Map<String, String> parseHostTokens(String spec) {
        Map<String, String> out = new LinkedHashMap<>();
        if (spec == null) {
            return out;
        }
        for (String part : spec.split(",")) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String host = part.substring(0, eq).trim();
            String token = part.substring(eq + 1).trim();
            if (!host.isEmpty() && !token.isEmpty()) {
                out.put(host, token);
            }
        }
        return out;
    }

    @EventListener(ApplicationReadyEvent.class)
    void warnAboutWeakTokens() {
        if (hostTokens.isEmpty() || (props.agentToken() != null && !props.agentToken().isBlank())) {
            check("SOC_AGENT_TOKEN", props.agentToken());
        }
        hostTokens.forEach((host, token) -> check("SOC_AGENT_HOST_TOKENS[" + host + "]", token));
        check("SOC_DASHBOARD_TOKEN", props.dashboardToken());
    }

    private void check(String name, String token) {
        if (token == null || token.isBlank()) {
            log.error("{} is not set: the matching API endpoints will reject every request", name);
        } else if (token.length() < 24) {
            log.warn("{} is shorter than 24 characters; generate one with `openssl rand -hex 32`", name);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        boolean ingest = req.getRequestURI().startsWith(INGEST_PREFIX);
        String sharedToken = ingest ? props.agentToken() : props.dashboardToken();
        boolean shared = sharedToken != null && !sharedToken.isBlank();
        if (!shared && !(ingest && !hostTokens.isEmpty())) {
            reject(res, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "API token not configured on the server");
            return;
        }

        String client = (ingest ? "agent|" : "dashboard|") + req.getRemoteAddr();
        Instant now = clock.instant();
        Instant until = lockedUntil.get(client);
        if (until != null && now.isBefore(until)) {
            res.setHeader("Retry-After", String.valueOf(Duration.between(now, until).toSeconds() + 1));
            reject(res, 429, "too many invalid tokens from this address; try again later");
            return;
        }

        String header = req.getHeader("Authorization");
        String token = header != null && header.startsWith("Bearer ") ? header.substring(7) : null;
        boolean ok = false;
        if (token != null) {
            if (shared && constantTimeEquals(token, sharedToken)) {
                ok = true;
            } else if (ingest) {
                for (Map.Entry<String, String> e : hostTokens.entrySet()) {
                    if (constantTimeEquals(token, e.getValue())) {
                        req.setAttribute(AGENT_HOST_ATTR, e.getKey());
                        ok = true;
                        break;
                    }
                }
            }
        }
        if (!ok) {
            recordFailure(client, now);
            reject(res, HttpServletResponse.SC_UNAUTHORIZED, "invalid or missing token");
            return;
        }
        failures.remove(client);
        chain.doFilter(req, res);
    }

    private void recordFailure(String client, Instant now) {
        Deque<Instant> times = failures.computeIfAbsent(client, k -> new ArrayDeque<>());
        synchronized (times) {
            times.addLast(now);
            while (!times.isEmpty() && times.peekFirst().isBefore(now.minus(FAILURE_WINDOW))) {
                times.removeFirst();
            }
            if (times.size() >= MAX_FAILURES) {
                times.clear();
                lockedUntil.put(client, now.plus(LOCKOUT));
                log.warn("{} sent {} invalid API tokens in {} min: refused for {} min",
                        client, MAX_FAILURES, FAILURE_WINDOW.toMinutes(), LOCKOUT.toMinutes());
            }
        }
        if (failures.size() > 10_000) { // spoofed-address flood: never let the map grow unbounded
            failures.clear();
        }
        lockedUntil.values().removeIf(t -> t.isBefore(now));
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static void reject(HttpServletResponse res, int status, String message) throws IOException {
        res.setStatus(status);
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.getWriter().write("{\"error\":\"" + message + "\"}");
    }
}
