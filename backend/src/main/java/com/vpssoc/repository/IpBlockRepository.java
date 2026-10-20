package com.vpssoc.repository;

import com.vpssoc.domain.IpBlock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface IpBlockRepository extends JpaRepository<IpBlock, Long> {

    @Query("""
            select b from IpBlock b
            where b.hostId = :hostId and b.ip = :ip and b.removedAt is null and b.expiresAt > :now
            order by b.expiresAt desc""")
    List<IpBlock> findActive(@Param("hostId") String hostId, @Param("ip") String ip, @Param("now") Instant now);

    default Optional<IpBlock> active(String hostId, String ip, Instant now) {
        return findActive(hostId, ip, now).stream().findFirst();
    }

    @Query("select b from IpBlock b where b.removedAt is null and b.expiresAt > :now order by b.createdAt desc")
    List<IpBlock> findAllActive(@Param("now") Instant now);

    @Query("select b from IpBlock b where b.ip = :ip and b.removedAt is null and b.expiresAt > :now")
    List<IpBlock> findActiveByIp(@Param("ip") String ip, @Param("now") Instant now);

    long countByCreatedAtAfter(Instant since);
}
