package com.vpssoc.api;

import com.vpssoc.api.ApiDtos.*;
import com.vpssoc.config.SocProperties;
import com.vpssoc.domain.ResponseAction;
import com.vpssoc.insight.Explanation;
import com.vpssoc.insight.IpProfileService;
import com.vpssoc.repository.ResponseActionRepository;
import com.vpssoc.response.ResponseService;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Active response for the dashboard: the action queue, approvals and IP blocks. */
@RestController
@RequestMapping("/api/v1/response")
public class ResponseController {

    private final ResponseService response;
    private final ResponseActionRepository actions;
    private final IpProfileService ips;
    private final SocProperties props;

    public ResponseController(ResponseService response, ResponseActionRepository actions, IpProfileService ips, SocProperties props) {
        this.response = response;
        this.actions = actions;
        this.ips = ips;
        this.props = props;
    }

    @GetMapping("/actions")
    public PageResponse<ActionView> actions(@RequestParam(required = false) List<ResponseAction.Status> status,
                                            @RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "50") int size) {
        var pageable = PageRequest.of(Math.max(page, 0), Math.clamp(size, 1, 200), Sort.by(Sort.Direction.DESC, "id"));
        var statuses = status == null || status.isEmpty() ? EnumSet.allOf(ResponseAction.Status.class) : EnumSet.copyOf(status);
        return PageResponse.of(actions.findByStatusIn(statuses, pageable), ActionView::of);
    }

    @PostMapping("/actions/{id}/approve")
    public ActionView approve(@PathVariable long id) {
        return ActionView.of(response.approve(id));
    }

    @PostMapping("/actions/{id}/dismiss")
    public ActionView dismiss(@PathVariable long id) {
        return ActionView.of(response.dismiss(id));
    }

    @GetMapping("/blocks")
    public List<BlockView> blocks() {
        return response.activeBlocks().stream().map(BlockView::of).toList();
    }

    @PostMapping("/blocks")
    public ActionView block(@RequestBody BlockRequest r) {
        if (r.hostId() == null || r.ip() == null) {
            throw new IllegalArgumentException("hostId e ip são obrigatórios");
        }
        int hours = r.ttlHours() == null ? 24 : Math.clamp(r.ttlHours(), 1, 24 * 30);
        return ActionView.of(response.blockManually(r.hostId(), r.ip().trim(), Duration.ofHours(hours), r.incidentId(), r.reason()));
    }

    @PostMapping("/blocks/{id}/unblock")
    public ActionView unblock(@PathVariable long id) {
        return ActionView.of(response.unblock(id));
    }

    @GetMapping("/ip/{ip}")
    public Explanation.IpProfile ip(@PathVariable String ip, @RequestParam(required = false) String hostId) {
        return ips.profile(hostId, ip);
    }

    /** Effective playbook policy, so the dashboard can show what runs on its own. */
    @GetMapping("/policy")
    public Map<String, Object> policy() {
        SocProperties.Response r = props.response();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", r.enabled());
        out.put("blockBruteForce", r.effective(r.blockBruteForce()));
        out.put("blockCompromise", r.effective(r.blockCompromise()));
        out.put("killProcess", r.effective(r.killProcess()));
        out.put("diskCleanup", r.effective(r.diskCleanup()));
        out.put("restartService", r.effective(r.restartService()));
        out.put("bruteForceBlockHours", r.bruteForceBlockTtl().toHours());
        out.put("compromiseBlockHours", r.compromiseBlockTtl().toHours());
        out.put("allowlist", r.allowlist() == null ? List.of() : r.allowlist());
        return out;
    }
}
