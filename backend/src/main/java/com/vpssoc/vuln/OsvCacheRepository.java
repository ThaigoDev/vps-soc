package com.vpssoc.vuln;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OsvCacheRepository extends JpaRepository<OsvCacheEntry, String> {
}
