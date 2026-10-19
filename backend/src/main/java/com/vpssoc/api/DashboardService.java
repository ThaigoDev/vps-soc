package com.vpssoc.api;

import com.vpssoc.api.ApiDtos.SourceIpStats;
import com.vpssoc.api.ApiDtos.Summary;
import com.vpssoc.api.ApiDtos.TimelineBucket;
import com.vpssoc.domain.*;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.HostRepository;
import com.vpssoc.repository.IncidentRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
@Transactional(readOnly = true)
public class DashboardService {

    private final EventRepository events;
    private final IncidentRepository incidents;
    private final HostRepository hosts;
    private final Clock clock;

    public DashboardService(EventRepository events, IncidentRepository incidents, HostRepository hosts, Clock clock) {
        this.events = events;
        this.incidents = incidents;
        this.hosts = hosts;
        this.clock = clock;
    }

    public Summary summary() {
        Instant since = clock.instant().minus(Duration.ofHours(24));
        List<Incident> open = incidents.findByStatusIn(IncidentStatus.ACTIVE);

        Map<Severity, Long> bySeverity = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            bySeverity.put(s, 0L);
        }
        int penalty = 0;
        for (Incident i : open) {
            bySeverity.merge(i.getSeverity(), 1L, Long::sum);
            penalty += i.getSeverity().scorePenalty();
        }
        int score = Math.max(0, 100 - penalty);
        String posture = score >= 80 ? "HEALTHY" : score >= 50 ? "AT_RISK" : "CRITICAL";

        List<Host> all = hosts.findAll();
        long online = all.stream().filter(h -> h.getStatus() == HostStatus.ONLINE).count();

        return new Summary(score, posture, bySeverity, open.size(),
                events.countByOccurredAtAfter(since),
                events.countByTypeInAndOccurredAtAfter(EventType.SSH_FAILURES, since),
                events.countDistinctSourceIps(EventType.SSH_FAILURES, since),
                online, all.size());
    }

    /** Hourly event counts by category, with empty hours filled in. */
    public List<TimelineBucket> timeline(int hours) {
        Instant end = clock.instant().truncatedTo(ChronoUnit.HOURS);
        Instant start = end.minus(Duration.ofHours(hours - 1L));

        Map<Instant, long[]> buckets = new LinkedHashMap<>();
        for (Instant h = start; !h.isAfter(end); h = h.plus(Duration.ofHours(1))) {
            buckets.put(h, new long[6]);
        }
        for (Object[] row : events.hourlyCounts(start)) {
            long[] b = buckets.get(toInstant(row[0]));
            Optional<EventType> type = EventType.parse((String) row[1]);
            if (b == null || type.isEmpty()) {
                continue;
            }
            int idx = switch (type.get().category()) {
                case AUTH_FAILURE -> 0;
                case AUTH_SUCCESS -> 1;
                case PRIVILEGE -> 2;
                case NETWORK -> 3;
                case AGENT -> 4;
                case FILE, PROCESS -> 5;
            };
            b[idx] += ((Number) row[2]).longValue();
        }
        return buckets.entrySet().stream()
                .map(e -> new TimelineBucket(e.getKey(), e.getValue()[0], e.getValue()[1], e.getValue()[2],
                        e.getValue()[3], e.getValue()[4], e.getValue()[5]))
                .toList();
    }

    public List<SourceIpStats> topSourceIps(int hours, int limit) {
        Instant since = clock.instant().minus(Duration.ofHours(hours));
        return events.topSourceIps(since, limit).stream()
                .map(r -> new SourceIpStats((String) r[0], ((Number) r[1]).longValue(), ((Number) r[2]).longValue(),
                        ((Number) r[3]).longValue(), toInstant(r[4])))
                .toList();
    }

    /** Native queries return different temporal types depending on driver/Hibernate version. */
    static Instant toInstant(Object o) {
        return switch (o) {
            case null -> null;
            case Instant i -> i;
            case Timestamp t -> t.toInstant();
            case OffsetDateTime odt -> odt.toInstant();
            case ZonedDateTime zdt -> zdt.toInstant();
            case LocalDateTime ldt -> ldt.toInstant(ZoneOffset.UTC);
            default -> throw new IllegalArgumentException("unexpected temporal type " + o.getClass());
        };
    }
}
