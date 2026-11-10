package com.vpssoc.vuln;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;

@Entity
@Table(name = "osv_cache")
public class OsvCacheEntry {

    @Id
    private String vulnId;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> data;

    private Instant fetchedAt;

    protected OsvCacheEntry() {
    }

    public OsvCacheEntry(String vulnId, Map<String, Object> data, Instant fetchedAt) {
        this.vulnId = vulnId;
        this.data = data;
        this.fetchedAt = fetchedAt;
    }

    public Map<String, Object> getData() { return data; }
    public Instant getFetchedAt() { return fetchedAt; }
}
