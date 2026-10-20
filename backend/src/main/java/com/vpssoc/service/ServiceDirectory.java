package com.vpssoc.service;

import com.vpssoc.repository.HostRepository;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Looks up the PM2 apps a host reported in its last heartbeat. */
@Component
public class ServiceDirectory {

    private final HostRepository hosts;

    public ServiceDirectory(HostRepository hosts) {
        this.hosts = hosts;
    }

    public List<Map<String, Object>> services(String hostId) {
        return hosts.findById(hostId).map(h -> h.getServices() == null ? List.<Map<String, Object>>of() : h.getServices())
                .orElse(List.of());
    }

    /** The app whose main process is pid (or the first of pids, e.g. a shell's parent). */
    public Optional<String> nameForPid(String hostId, Object... pids) {
        List<Map<String, Object>> list = services(hostId);
        for (Object p : pids) {
            if (!(p instanceof Number n) || n.intValue() <= 1) {
                continue;
            }
            for (Map<String, Object> s : list) {
                if (s.get("pid") instanceof Number sp && sp.intValue() == n.intValue()) {
                    return Optional.of(String.valueOf(s.get("name")));
                }
            }
        }
        return Optional.empty();
    }

    public Optional<Map<String, Object>> byName(String hostId, String name) {
        return services(hostId).stream().filter(s -> name.equals(s.get("name"))).findFirst();
    }
}
