package com.vpssoc.geo;

import com.vpssoc.domain.Host;
import com.vpssoc.response.IpClassifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Public IP of each server for the map, from SOC_SERVER_PUBLIC_IP:
 * <pre>
 *   SOC_SERVER_PUBLIC_IP=82.25.79.73                      (every server)
 *   SOC_SERVER_PUBLIC_IP=srv731680=82.25.79.73,web2=1.2.3.4  (per server id)
 * </pre>
 * Order of preference: .env, then the IP typed in the dashboard, then the one the agent
 * reports, then the address the agent connects from.
 */
@Component
public class ServerLocations {

    public record Resolved(String ip, String source) {
    }

    private final String fallback;
    private final Map<String, String> perHost = new HashMap<>();

    public ServerLocations(@Value("${soc.geoip.server-public-ip:}") String config) {
        String def = null;
        for (String part : config == null ? new String[0] : config.split("[,;\\s]+")) {
            if (part.isBlank()) {
                continue;
            }
            int eq = part.indexOf('=');
            if (eq < 0) {
                def = valid(part.trim());
            } else {
                String ip = valid(part.substring(eq + 1).trim());
                if (ip != null) {
                    perHost.put(part.substring(0, eq).trim(), ip);
                }
            }
        }
        this.fallback = def;
    }

    private static String valid(String ip) {
        if (IpClassifier.kind(ip) != IpClassifier.Kind.PUBLIC) {
            throw new IllegalArgumentException("SOC_SERVER_PUBLIC_IP: '" + ip + "' não é um IP público válido");
        }
        return ip;
    }

    public Resolved resolve(Host h) {
        String env = perHost.getOrDefault(h.getId(), fallback);
        if (env != null) return new Resolved(env, "ENV");
        if (h.getManualIp() != null) return new Resolved(h.getManualIp(), "MANUAL");
        if (h.getPublicIp() != null) return new Resolved(h.getPublicIp(), "AGENT");
        return new Resolved(h.getLastIp(), "CONNECTION");
    }
}
