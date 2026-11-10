package com.vpssoc.repository;

import com.vpssoc.domain.ServiceSample;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface ServiceSampleRepository extends JpaRepository<ServiceSample, Long> {

    List<ServiceSample> findByHostIdAndNameAndRecordedAtAfterOrderByRecordedAtAsc(String hostId, String name, Instant since);

    List<ServiceSample> findTop2ByHostIdAndNameOrderByRecordedAtDesc(String hostId, String name);

    /** Lowest restart counter per app since :since (the counter only grows, so now − min = restarts in the window). */
    @Query("""
            select s.name, min(s.restarts) from ServiceSample s
            where s.hostId = :hostId and s.recordedAt > :since group by s.name""")
    List<Object[]> minRestartsSince(@Param("hostId") String hostId, @Param("since") Instant since);

    /** Availability per app since :since: online share, probe success, latency percentiles, error lines in the last hour. */
    @Query(value = """
            select name,
                   count(*),
                   count(*) filter (where status = 'online'),
                   count(probe_ok),
                   count(*) filter (where probe_ok),
                   percentile_cont(0.5) within group (order by latency_ms),
                   percentile_cont(0.95) within group (order by latency_ms),
                   coalesce(sum(error_lines) filter (where recorded_at > :hourAgo), 0)
            from service_samples
            where host_id = :hostId and recorded_at > :since
            group by name""", nativeQuery = true)
    List<Object[]> availability(@Param("hostId") String hostId, @Param("since") Instant since, @Param("hourAgo") Instant hourAgo);

    @Modifying
    @Query("delete from ServiceSample s where s.recordedAt < :before")
    int deleteOlderThan(@Param("before") Instant before);
}
