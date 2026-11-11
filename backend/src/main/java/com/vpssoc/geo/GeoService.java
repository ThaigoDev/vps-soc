package com.vpssoc.geo;

import com.vpssoc.response.IpClassifier;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * IP → place, for the world map. Answers from the cache right away and looks up missing
 * addresses one at a time in the background (the free services are rate limited), so the
 * map fills in over the next refreshes instead of making the dashboard wait.
 */
@Service
public class GeoService {

    private static final Logger log = LoggerFactory.getLogger(GeoService.class);
    private static final Duration KEEP_OK = Duration.ofDays(30);
    private static final Duration RETRY_FAILED = Duration.ofHours(6);
    private static final int MAX_PENDING = 500;
    private static final long PAUSE_MS = 400;

    private final IpGeoRepository cache;
    private final GeoClient client;
    private final Clock clock;
    private final boolean enabled;
    private final Set<String> pending = ConcurrentHashMap.newKeySet();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "geoip");
        t.setDaemon(true);
        return t;
    });

    public GeoService(IpGeoRepository cache, GeoClient client, Clock clock,
                      @Value("${soc.geoip.enabled:true}") boolean enabled) {
        this.cache = cache;
        this.client = client;
        this.clock = clock;
        this.enabled = enabled;
    }

    public boolean enabled() {
        return enabled;
    }

    public int pending() {
        return pending.size();
    }

    /** Known locations for these IPs (public addresses only); queues lookups for the rest. */
    public Map<String, IpGeo> locate(Collection<String> ips) {
        Set<String> wanted = new LinkedHashSet<>();
        for (String ip : ips) {
            if (ip != null && IpClassifier.kind(ip) == IpClassifier.Kind.PUBLIC) {
                wanted.add(ip);
            }
        }
        Map<String, IpGeo> out = new HashMap<>();
        if (wanted.isEmpty()) {
            return out;
        }
        var now = clock.instant();
        Map<String, IpGeo> known = new HashMap<>();
        cache.findAllById(wanted).forEach(g -> known.put(g.getIp(), g));
        for (String ip : wanted) {
            IpGeo g = known.get(ip);
            if (g != null && g.isOk()) {
                out.put(ip, g);
            }
            boolean stale = g == null || g.getFetchedAt().plus(g.isOk() ? KEEP_OK : RETRY_FAILED).isBefore(now);
            if (stale) {
                enqueue(ip);
            }
        }
        return out;
    }

    private void enqueue(String ip) {
        if (!enabled || pending.size() >= MAX_PENDING || !pending.add(ip)) {
            return;
        }
        worker.submit(() -> {
            try {
                IpGeo g;
                try {
                    g = new IpGeo(ip, client.locate(ip).orElse(null), clock.instant());
                } catch (RuntimeException e) {
                    log.debug("geoip lookup failed for {}: {}", ip, e.toString());
                    g = new IpGeo(ip, null, clock.instant());
                }
                cache.save(g);
                Thread.sleep(PAUSE_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException e) {
                log.warn("geoip cache write failed for {}: {}", ip, e.toString());
            } finally {
                pending.remove(ip);
            }
        });
    }

    @PreDestroy
    void stop() {
        worker.shutdownNow();
    }
}
