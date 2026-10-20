package com.vpssoc.repository;

import com.vpssoc.domain.Incident;
import com.vpssoc.domain.IncidentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface IncidentRepository extends JpaRepository<Incident, Long>, JpaSpecificationExecutor<Incident> {

    Optional<Incident> findFirstByHostIdAndRuleIdAndDedupKeyAndStatusIn(
            String hostId, String ruleId, String dedupKey, Collection<IncidentStatus> statuses);

    List<Incident> findByHostIdAndRuleIdAndStatusIn(String hostId, String ruleId, Collection<IncidentStatus> statuses);

    List<Incident> findByStatusIn(Collection<IncidentStatus> statuses);

    List<Incident> findByHostIdAndSourceIpAndStatusIn(String hostId, String sourceIp, Collection<IncidentStatus> statuses);

    long countBySourceIp(String sourceIp);

    Optional<Incident> findFirstByHostIdAndRuleIdAndDedupKeyOrderByIdDesc(String hostId, String ruleId, String dedupKey);

    /** SOC timing KPIs over incidents created since :since (seconds). */
    @Query(value = """
            select avg(greatest(0, extract(epoch from created_at - first_seen))),
                   avg(extract(epoch from acknowledged_at - created_at)) filter (where acknowledged_at is not null),
                   avg(extract(epoch from resolved_at - created_at)) filter (where status = 'RESOLVED'),
                   avg(greatest(0, extract(epoch from contained_at - created_at))) filter (where contained_at is not null),
                   count(*),
                   count(*) filter (where status = 'RESOLVED'),
                   count(*) filter (where status = 'FALSE_POSITIVE'),
                   count(*) filter (where contained_at is not null),
                   count(*) filter (where contained_at is not null and not exists (
                       select 1 from response_actions a where a.incident_id = i.id and a.mode = 'MANUAL' and a.status = 'SUCCEEDED')),
                   count(*) filter (where status in ('OPEN', 'ACKNOWLEDGED'))
            from incidents i where created_at > :since""", nativeQuery = true)
    List<Object[]> kpis(@Param("since") java.time.Instant since);

    @Query(value = """
            select rule_id, count(*), count(*) filter (where status = 'FALSE_POSITIVE')
            from incidents where created_at > :since group by rule_id order by 2 desc limit 10""", nativeQuery = true)
    List<Object[]> byRule(@Param("since") java.time.Instant since);

    @Query(value = """
            select to_char(created_at at time zone 'America/Sao_Paulo', 'YYYY-MM-DD'), count(*)
            from incidents where created_at > :since group by 1""", nativeQuery = true)
    List<Object[]> openedPerDay(@Param("since") java.time.Instant since);

    @Query(value = """
            select to_char(resolved_at at time zone 'America/Sao_Paulo', 'YYYY-MM-DD'), count(*)
            from incidents where resolved_at > :since and status in ('RESOLVED', 'FALSE_POSITIVE') group by 1""", nativeQuery = true)
    List<Object[]> closedPerDay(@Param("since") java.time.Instant since);

    @Modifying
    @Query(value = """
            insert into incident_events (incident_id, event_id)
            values (:incidentId, :eventId)
            on conflict do nothing""", nativeQuery = true)
    int link(@Param("incidentId") long incidentId, @Param("eventId") long eventId);

    /** Earliest evidence time, so first_seen covers events linked from before the trigger. */
    @Query(value = """
            select min(e.occurred_at) from events e
            join incident_events ie on ie.event_id = e.id
            where ie.incident_id = :incidentId""", nativeQuery = true)
    Optional<java.time.Instant> earliestEvidence(@Param("incidentId") long incidentId);
}
