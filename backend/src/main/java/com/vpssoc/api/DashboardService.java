package com.vpssoc.api;

import com.vpssoc.api.ApiDtos.SourceIpStats;
import com.vpssoc.api.ApiDtos.Summary;
import com.vpssoc.api.ApiDtos.TimelineBucket;
import com.vpssoc.domain.*;
import com.vpssoc.repository.EventRepository;
import com.vpssoc.repository.HostRepository;
import com.vpssoc.repository.IncidentRepository;
import com.vpssoc.repository.IpBlockRepository;
import com.vpssoc.repository.ResponseActionRepository;
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
    private final ResponseActionRepository actions;
    private final IpBlockRepository blocks;

    public DashboardService(EventRepository events, IncidentRepository incidents, HostRepository hosts, Clock clock,
                            ResponseActionRepository actions, IpBlockRepository blocks) {
        this.actions = actions;
        this.blocks = blocks;
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
                case AGENT, RESPONSE, SERVICE -> 4;
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

    /**
     * SOC performance over the last {@code days}: mean time to detect (first evidence → incident),
     * acknowledge, contain and resolve, false-positive rate, how much was contained without a
     * human, response activity and the current exposure.
     */
    public ApiDtos.Kpis kpis(int days) {
        Instant now = clock.instant();
        Instant since = now.minus(Duration.ofDays(days));
        Object[] k = incidents.kpis(since).stream().findFirst().orElse(new Object[10]);
        long opened = num(k[4]);
        long fp = num(k[6]);
        long contained = num(k[7]);
        long auto = num(k[8]);

        long actionsAuto = 0, actionsManual = 0, actionsFailed = 0;
        for (Object[] r : actions.countByStatusAndMode(since)) {
            ResponseAction.Status st = (ResponseAction.Status) r[0];
            long n = num(r[2]);
            if (st == ResponseAction.Status.SUCCEEDED) {
                if (r[1] == ResponseAction.Mode.AUTO) actionsAuto += n;
                else actionsManual += n;
            } else if (st == ResponseAction.Status.FAILED || st == ResponseAction.Status.REJECTED) {
                actionsFailed += n;
            }
        }

        long dropped = 0;
        long maxLag = 0;
        for (Host h : hosts.findAll()) {
            maxLag = Math.max(maxLag, Duration.between(h.getLastSeen(), now).toSeconds());
            if (h.getPosture() != null && h.getPosture().get("firewall") instanceof Map<?, ?> fw
                    && fw.get("droppedPackets") instanceof Number n) {
                dropped += n.longValue();
            }
        }

        Map<String, long[]> perDay = new TreeMap<>();
        LocalDate today = LocalDate.now(ZoneId.of("America/Sao_Paulo"));
        for (int d = Math.min(days, 14) - 1; d >= 0; d--) {
            perDay.put(today.minusDays(d).toString(), new long[2]);
        }
        incidents.openedPerDay(since).forEach(r -> Optional.ofNullable(perDay.get((String) r[0])).ifPresent(a -> a[0] += num(r[1])));
        incidents.closedPerDay(since).forEach(r -> Optional.ofNullable(perDay.get((String) r[0])).ifPresent(a -> a[1] += num(r[1])));

        return new ApiDtos.Kpis(days, dbl(k[0]), dbl(k[1]), dbl(k[2]), dbl(k[3]),
                opened, num(k[5]), fp, opened == 0 ? 0 : (double) fp / opened,
                contained, auto, contained == 0 ? 0 : (double) auto / contained, num(k[9]),
                actionsAuto, actionsManual, actionsFailed, actions.countByStatus(ResponseAction.Status.PROPOSED),
                blocks.findAllActive(now).size(), dropped,
                events.countByOccurredAtAfter(now.minus(Duration.ofHours(1))) / 60.0, maxLag,
                incidents.byRule(since).stream().map(r -> new ApiDtos.RuleCount((String) r[0], num(r[1]), num(r[2]))).toList(),
                events.topTargetedUsernames(now.minus(Duration.ofHours(24)), 8).stream()
                        .map(r -> new ApiDtos.NameCount((String) r[0], num(r[1]))).toList(),
                perDay.entrySet().stream().map(e -> new ApiDtos.DayCount(e.getKey(), e.getValue()[0], e.getValue()[1])).toList());
    }

    private static long num(Object o) {
        return o instanceof Number n ? n.longValue() : 0;
    }

    private static Double dbl(Object o) {
        return o instanceof Number n ? n.doubleValue() : null;
    }

    /** Native queries return different temporal types depending on driver/Hibernate version. */
    public static Instant toInstant(Object o) {
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
