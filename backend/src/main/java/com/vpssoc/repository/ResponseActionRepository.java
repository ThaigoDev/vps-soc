package com.vpssoc.repository;

import com.vpssoc.domain.ResponseAction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

public interface ResponseActionRepository extends JpaRepository<ResponseAction, Long> {

    List<ResponseAction> findByHostIdAndStatusOrderByIdAsc(String hostId, ResponseAction.Status status);

    List<ResponseAction> findByIncidentIdOrderByIdAsc(Long incidentId);

    List<ResponseAction> findByHostIdAndTargetOrderByIdAsc(String hostId, String target);

    List<ResponseAction> findByHostIdAndTypeAndTargetAndStatusIn(String hostId, ResponseAction.Type type, String target,
                                                                Collection<ResponseAction.Status> statuses);

    boolean existsByHostIdAndTypeAndTargetAndStatusIn(String hostId, ResponseAction.Type type, String target,
                                                      Collection<ResponseAction.Status> statuses);

    boolean existsByHostIdAndTypeAndTargetAndCreatedAtAfter(String hostId, ResponseAction.Type type, String target, Instant since);

    List<ResponseAction> findByStatusAndCreatedAtBefore(ResponseAction.Status status, Instant before);

    List<ResponseAction> findByStatusAndDispatchedAtBefore(ResponseAction.Status status, Instant before);

    Page<ResponseAction> findByStatusIn(Collection<ResponseAction.Status> statuses, Pageable page);

    long countByStatus(ResponseAction.Status status);

    boolean existsByHostIdAndTypeAndTargetAndStatusAndCompletedAtAfter(String hostId, ResponseAction.Type type, String target,
                                                                    ResponseAction.Status status, Instant since);

    @Query("""
            select a.status, a.mode, count(a) from ResponseAction a
            where a.createdAt > :since group by a.status, a.mode""")
    List<Object[]> countByStatusAndMode(@Param("since") Instant since);
}
