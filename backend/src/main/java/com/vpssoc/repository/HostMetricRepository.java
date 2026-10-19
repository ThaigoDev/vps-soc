package com.vpssoc.repository;

import com.vpssoc.domain.HostMetric;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface HostMetricRepository extends JpaRepository<HostMetric, Long> {

    List<HostMetric> findByHostIdAndRecordedAtAfterOrderByRecordedAtAsc(String hostId, Instant since);

    @Modifying
    @Query("delete from HostMetric m where m.recordedAt < :before")
    int deleteOlderThan(@Param("before") Instant before);
}
