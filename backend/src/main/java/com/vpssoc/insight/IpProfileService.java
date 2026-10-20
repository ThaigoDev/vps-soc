package com.vpssoc.insight;

import com.vpssoc.api.DashboardService;
import com.vpssoc.config.SocProperties;
import com.vpssoc.domain.IpBlock;
import com.vpssoc.insight.Explanation.IpProfile;
import com.vpssoc.insight.Explanation.UserCount;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.IncidentRepository;
import com.vpssoc.response.IpClassifier;
import com.vpssoc.response.ResponseService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/** Everything the SOC knows about one source address, across all its history. */
@Service
public class IpProfileService {

    private final EventRepository events;
    private final IncidentRepository incidents;
    private final ResponseService response;
    private final SocProperties props;

    public IpProfileService(EventRepository events, IncidentRepository incidents, ResponseService response, SocProperties props) {
        this.events = events;
        this.incidents = incidents;
        this.response = response;
        this.props = props;
    }

    @Transactional(readOnly = true)
    public IpProfile profile(String hostId, String ip) {
        IpClassifier.Kind kind = IpClassifier.kind(ip);
        Object[] t = events.ipTotals(ip).stream().findFirst().orElse(new Object[5]);
        List<UserCount> top = events.ipTopUsernames(ip).stream()
                .map(r -> new UserCount((String) r[0], ((Number) r[1]).longValue()))
                .toList();
        Optional<IpBlock> block = hostId == null ? Optional.empty() : response.activeBlock(hostId, ip);
        long successes = num(t[3]);
        return new IpProfile(ip, kind.name(), IpClassifier.kindLabel(kind), response.classifier().protectedBy(ip),
                props.detection().trustedSshSource(ip),
                DashboardService.toInstant(t[0]), DashboardService.toInstant(t[1]),
                num(t[2]), successes, num(t[4]), top, incidents.countBySourceIp(ip),
                block.map(IpBlock::getExpiresAt).orElse(null),
                block.map(b -> b.getOrigin().name()).orElse(null),
                successes > 0);
    }

    private static long num(Object o) {
        return o instanceof Number n ? n.longValue() : 0;
    }
}
