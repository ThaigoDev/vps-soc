package com.vpssoc.repository;

import com.vpssoc.domain.EventType;
import com.vpssoc.domain.SecurityEvent;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

public interface EventRepository extends JpaRepository<SecurityEvent, Long>, JpaSpecificationExecutor<SecurityEvent> {

    long countByHostIdAndSourceIpAndTypeInAndOccurredAtBetween(
            String hostId, String sourceIp, Collection<EventType> types, Instant from, Instant to);

    @Query("""
            select count(distinct e.username) from SecurityEvent e
            where e.hostId = :hostId and e.sourceIp = :ip and e.type in :types
              and e.occurredAt between :from and :to""")
    long countDistinctUsernames(@Param("hostId") String hostId, @Param("ip") String ip,
                                @Param("types") Collection<EventType> types,
                                @Param("from") Instant from, @Param("to") Instant to);

    @Query("""
            select e.id from SecurityEvent e
            where e.hostId = :hostId and e.sourceIp = :ip and e.type in :types
              and e.occurredAt between :from and :to
            order by e.occurredAt desc""")
    List<Long> findIds(@Param("hostId") String hostId, @Param("ip") String ip,
                       @Param("types") Collection<EventType> types,
                       @Param("from") Instant from, @Param("to") Instant to, Pageable page);

    boolean existsByHostIdAndTypeAndUsernameAndSourceIpAndIdNot(
            String hostId, EventType type, String username, String sourceIp, Long id);

    @Query("""
            select count(e) > 0 from SecurityEvent e
            where e.hostId = :hostId and e.sourceIp = :ip and e.type = com.vpssoc.domain.EventType.SSH_LOGIN_SUCCESS
              and e.occurredAt < :before""")
    boolean existsSuccessBefore(@Param("hostId") String hostId, @Param("ip") String ip, @Param("before") Instant before);

    @Query(value = """
            select min(occurred_at), max(occurred_at),
                   count(*) filter (where type in ('SSH_FAILED_LOGIN', 'SSH_INVALID_USER')),
                   count(*) filter (where type = 'SSH_LOGIN_SUCCESS'),
                   count(distinct username) filter (where type in ('SSH_FAILED_LOGIN', 'SSH_INVALID_USER'))
            from events where source_ip = :ip""", nativeQuery = true)
    List<Object[]> ipTotals(@Param("ip") String ip);

    @Query(value = """
            select username, count(*) from events
            where source_ip = :ip and username is not null and type in ('SSH_FAILED_LOGIN', 'SSH_INVALID_USER')
            group by username order by 2 desc limit 8""", nativeQuery = true)
    List<Object[]> ipTopUsernames(@Param("ip") String ip);

    @Query(value = """
            select username, count(*) from events
            where occurred_at > :since and username is not null and type in ('SSH_FAILED_LOGIN', 'SSH_INVALID_USER')
            group by username order by 2 desc limit :limit""", nativeQuery = true)
    List<Object[]> topTargetedUsernames(@Param("since") Instant since, @Param("limit") int limit);

    /**
     * Restarts of one PM2 app since :since, summing the agent's per-scan deltas per instance
     * and taking the busiest instance (a cluster reload restarts every instance once).
     */
    @Query(value = """
            select coalesce(max(n), 0) from (
                select sum(coalesce((metadata->>'delta')::int, 1)) as n from events
                where host_id = :hostId and type = 'SERVICE_RESTARTED' and metadata->>'service' = :name
                  and occurred_at > :since
                group by metadata->>'pmId') per_instance""", nativeQuery = true)
    long sumServiceRestarts(@Param("hostId") String hostId, @Param("name") String name, @Param("since") Instant since);

    @Query(value = """
            select id from events
            where host_id = :hostId and type like 'SERVICE_%' and metadata->>'service' = :name and occurred_at > :since
            order by occurred_at desc limit 200""", nativeQuery = true)
    List<Long> serviceEventIds(@Param("hostId") String hostId, @Param("name") String name, @Param("since") Instant since);

    @Query(value = """
            select e.* from events e
            where e.host_id = :hostId and e.type like 'SERVICE_%' and e.metadata->>'service' = :name and e.occurred_at > :since
            order by e.occurred_at desc limit 200""", nativeQuery = true)
    List<SecurityEvent> serviceEvents(@Param("hostId") String hostId, @Param("name") String name, @Param("since") Instant since);

    long countByOccurredAtAfter(Instant since);

    long countByTypeInAndOccurredAtAfter(Collection<EventType> types, Instant since);

    @Query("""
            select count(distinct e.sourceIp) from SecurityEvent e
            where e.type in :types and e.occurredAt > :since""")
    long countDistinctSourceIps(@Param("types") Collection<EventType> types, @Param("since") Instant since);

    @Query(value = """
            select source_ip,
                   count(*) filter (where type in ('SSH_FAILED_LOGIN', 'SSH_INVALID_USER')) as failures,
                   count(*) filter (where type = 'SSH_LOGIN_SUCCESS')                       as successes,
                   count(distinct username)                                                 as usernames,
                   max(occurred_at)                                                         as last_seen
            from events
            where source_ip is not null and occurred_at > :since
            group by source_ip
            order by failures desc, successes desc
            limit :limit""", nativeQuery = true)
    List<Object[]> topSourceIps(@Param("since") Instant since, @Param("limit") int limit);

    @Query(value = """
            select date_trunc('hour', occurred_at) as bucket, type, count(*)
            from events
            where occurred_at > :since
            group by 1, 2
            order by 1""", nativeQuery = true)
    List<Object[]> hourlyCounts(@Param("since") Instant since);

    @Query(value = """
            select e.* from events e
            join incident_events ie on ie.event_id = e.id
            where ie.incident_id = :incidentId
            order by e.occurred_at, e.id
            limit 1000""", nativeQuery = true)
    List<SecurityEvent> findByIncident(@Param("incidentId") long incidentId);

    /** Deletes old events except those that are evidence of an incident. */
    @Modifying
    @Query(value = """
            delete from events e
            where e.occurred_at < :before
              and not exists (select 1 from incident_events ie where ie.event_id = e.id)""", nativeQuery = true)
    int deleteOlderThan(@Param("before") Instant before);
}
