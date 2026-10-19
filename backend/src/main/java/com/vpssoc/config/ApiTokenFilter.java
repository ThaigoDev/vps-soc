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

/**
 * Bearer-token auth for the API: agents use {@code soc.agent-token} on /api/v1/ingest/**,
 * the dashboard uses {@code soc.dashboard-token} on everything else under /api.
 */
@Component
public class ApiTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ApiTokenFilter.class);
    private static final String INGEST_PREFIX = "/api/v1/ingest/";

    private final SocProperties props;

    public ApiTokenFilter(SocProperties props) {
        this.props = props;
    }

    @EventListener(ApplicationReadyEvent.class)
    void warnAboutWeakTokens() {
        check("SOC_AGENT_TOKEN", props.agentToken());
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
        String expected = req.getRequestURI().startsWith(INGEST_PREFIX) ? props.agentToken() : props.dashboardToken();
        if (expected == null || expected.isBlank()) {
            reject(res, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "API token not configured on the server");
            return;
        }
        String header = req.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ") || !constantTimeEquals(header.substring(7), expected)) {
            reject(res, HttpServletResponse.SC_UNAUTHORIZED, "invalid or missing token");
            return;
        }
        chain.doFilter(req, res);
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
