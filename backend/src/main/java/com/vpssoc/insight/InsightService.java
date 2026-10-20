package com.vpssoc.insight;

import com.vpssoc.config.SocProperties;
import com.vpssoc.domain.Incident;
import com.vpssoc.domain.ResponseAction;
import com.vpssoc.domain.SecurityEvent;
import com.vpssoc.insight.Explanation.IpProfile;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.HostRepository;
import com.vpssoc.repository.ResponseActionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Gathers the evidence, IP history and actions of an incident and explains it. */
@Service
public class InsightService {

    public record Insight(Explanation explanation, IpProfile ip, List<ResponseAction> actions, List<SecurityEvent> events) {
    }

    private final EventRepository events;
    private final HostRepository hosts;
    private final ResponseActionRepository actions;
    private final IpProfileService ips;
    private final IncidentExplainer explainer;
    private final SocProperties props;

    public InsightService(EventRepository events, HostRepository hosts, ResponseActionRepository actions, IpProfileService ips,
                          IncidentExplainer explainer, SocProperties props) {
        this.events = events;
        this.hosts = hosts;
        this.actions = actions;
        this.ips = ips;
        this.explainer = explainer;
        this.props = props;
    }

    @Transactional(readOnly = true)
    public Insight insight(Incident inc) {
        List<SecurityEvent> evs = events.findByIncident(inc.getId());
        IpProfile ip = inc.getSourceIp() == null ? null : ips.profile(inc.getHostId(), inc.getSourceIp());
        // Actions of this incident, plus blocks of its source IP started by a sibling incident
        // (e.g. the brute force that preceded a compromise).
        Map<Long, ResponseAction> byId = new TreeMap<>();
        actions.findByIncidentIdOrderByIdAsc(inc.getId()).forEach(a -> byId.put(a.getId(), a));
        if (inc.getSourceIp() != null) {
            actions.findByHostIdAndTargetOrderByIdAsc(inc.getHostId(), inc.getSourceIp()).stream()
                    .filter(a -> a.getStatus() != ResponseAction.Status.DISMISSED || inc.getId().equals(a.getIncidentId()))
                    .forEach(a -> byId.put(a.getId(), a));
        }
        List<ResponseAction> acts = List.copyOf(byId.values());
        Explanation e = explainer.explain(new IncidentExplainer.Context(inc, evs, ip, hosts.findById(inc.getHostId()).orElse(null),
                acts, props.response()));
        return new Insight(e, ip, acts, evs);
    }
}
