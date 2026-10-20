package com.vpssoc.api;

import com.vpssoc.api.ApiDtos.ActionView;
import com.vpssoc.config.SocProperties;
import com.vpssoc.domain.ResponseAction;
import com.vpssoc.response.ResponseService;
import com.vpssoc.service.ServiceDirectory;
import com.vpssoc.service.ServiceHealthService;
import com.vpssoc.service.ServiceHealthService.ServiceDetail;
import com.vpssoc.service.ServiceHealthService.ServiceView;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** PM2 apps per host: status, health, history, incidents, and a manual restart. */
@RestController
@RequestMapping("/api/v1/services")
public class ServiceController {

    private final ServiceHealthService health;
    private final ServiceDirectory directory;
    private final ResponseService response;

    public ServiceController(ServiceHealthService health, ServiceDirectory directory, ResponseService response) {
        this.health = health;
        this.directory = directory;
        this.response = response;
    }

    @GetMapping
    public List<ServiceView> all() {
        return health.all();
    }

    @GetMapping("/{hostId}/{name}")
    public ServiceDetail detail(@PathVariable String hostId, @PathVariable String name, @RequestParam(defaultValue = "24") int hours) {
        return health.detail(hostId, name, Math.clamp(hours, 1, 24 * 7))
                .orElseThrow(() -> new IllegalArgumentException("app %s não encontrado em %s".formatted(name, hostId)));
    }

    /** Queues `pm2 restart <id>` for the agent (the agent re-checks the id still is that app). */
    @PostMapping("/{hostId}/{name}/restart")
    public ActionView restart(@PathVariable String hostId, @PathVariable String name) {
        Map<String, Object> s = directory.byName(hostId, name)
                .orElseThrow(() -> new IllegalArgumentException("app %s não encontrado em %s".formatted(name, hostId)));
        Map<String, Object> params = new HashMap<>();
        params.put("name", s.get("name"));
        params.put("pmId", s.get("pmId"));
        params.put("pm2Home", s.get("pm2Home"));
        return ActionView.of(response.request(hostId, null, ResponseAction.Type.PM2_RESTART,
                        "pm2:" + s.get("pm2Home") + "#" + s.get("pmId"), params, SocProperties.Policy.AUTO,
                        "Reinício manual pelo painel: pm2 restart " + name)
                .orElseThrow(() -> new IllegalStateException("já existe um reinício em andamento para " + name)));
    }
}
