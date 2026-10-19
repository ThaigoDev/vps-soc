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
