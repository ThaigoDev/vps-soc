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

    /** Lowest restart counter per app since :since (the counter only grows, so now − min = restarts in the window). */
    @Query("""
            select s.name, min(s.restarts) from ServiceSample s
            where s.hostId = :hostId and s.recordedAt > :since group by s.name""")
    List<Object[]> minRestartsSince(@Param("hostId") String hostId, @Param("since") Instant since);

    @Modifying
    @Query("delete from ServiceSample s where s.recordedAt < :before")
    int deleteOlderThan(@Param("before") Instant before);
}
