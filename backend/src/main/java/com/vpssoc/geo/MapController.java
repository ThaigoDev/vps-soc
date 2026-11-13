package com.vpssoc.geo;

import com.vpssoc.api.ApiDtos.SourceIpStats;
import com.vpssoc.api.DashboardService;
import com.vpssoc.domain.Host;
import com.vpssoc.domain.HostStatus;
import com.vpssoc.repository.HostRepository;
import com.vpssoc.repository.IpBlockRepository;
import com.vpssoc.response.IpClassifier;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.Clock;
import java.util.*;
import java.util.stream.Collectors;

/** World map of the servers and of where the attacks come from. */
@RestController
@RequestMapping("/api/v1")
public class MapController {

    public record GeoView(String country, String countryCode, String region, String city, double lat, double lon, String org) {
        static GeoView of(IpGeo g) {
            return g == null ? null : new GeoView(g.getCountry(), g.getCountryCode(), g.getRegion(), g.getCity(), g.getLat(), g.getLon(), g.getOrg());
        }
    }

    /** {@code ipSource}: ENV (SOC_SERVER_PUBLIC_IP), MANUAL (set in the dashboard), AGENT (reported by the server) or CONNECTION (address it connects from). */
    public record MapServer(String hostId, HostStatus status, String ip, String ipSource, boolean publicIp, GeoView geo) {
    }

    public record MapAttacker(String ip, long failures, long successes, long usernames, boolean blocked, GeoView geo) {
    }

    public record MapCountry(String code, String name, int ips, long failures, long successes) {
    }

    public record AttackMap(int hours, boolean geoEnabled, int pendingLookups, List<MapServer> servers,
                            List<MapAttacker> attackers, List<MapCountry> countries) {
    }

    public record LocationChange(String ip) {
    }

    private final HostRepository hosts;
    private final DashboardService dashboard;
    private final IpBlockRepository blocks;
    private final GeoService geo;
    private final Clock clock;
    private final ServerLocations locations;

    public MapController(HostRepository hosts, DashboardService dashboard, IpBlockRepository blocks, GeoService geo, Clock clock,
                         ServerLocations locations) {
        this.locations = locations;
        this.hosts = hosts;
        this.dashboard = dashboard;
        this.blocks = blocks;
        this.geo = geo;
        this.clock = clock;
    }

    @GetMapping("/dashboard/map")
    public AttackMap map(@RequestParam(defaultValue = "24") int hours, @RequestParam(defaultValue = "60") int limit) {
        int h = Math.clamp(hours, 1, 24 * 30);
        List<Host> all = hosts.findAllByOrderByIdAsc();
        List<SourceIpStats> top = dashboard.topSourceIps(h, Math.clamp(limit, 1, 200));
        Set<String> blocked = blocks.findAllActive(clock.instant()).stream().map(b -> b.getIp()).collect(Collectors.toSet());

        List<String> ips = new ArrayList<>();
        all.forEach(x -> ips.add(locations.resolve(x).ip()));
        top.forEach(t -> ips.add(t.ip()));
        Map<String, IpGeo> found = geo.locate(ips);

        List<MapServer> servers = all.stream().map(x -> {
            var r = locations.resolve(x);
            String ip = r.ip();
            return new MapServer(x.getId(), x.getStatus(), ip, r.source(),
                    ip != null && IpClassifier.kind(ip) == IpClassifier.Kind.PUBLIC, GeoView.of(found.get(ip)));
        }).toList();

        List<MapAttacker> attackers = top.stream()
                .filter(t -> t.ip() != null && IpClassifier.kind(t.ip()) == IpClassifier.Kind.PUBLIC)
                .map(t -> new MapAttacker(t.ip(), t.failures(), t.successes(), t.usernames(), blocked.contains(t.ip()), GeoView.of(found.get(t.ip()))))
                .toList();

        Map<String, long[]> byCountry = new LinkedHashMap<>();
        Map<String, String> names = new HashMap<>();
        for (MapAttacker a : attackers) {
            if (a.geo() == null || a.geo().countryCode() == null) {
                continue;
            }
            long[] c = byCountry.computeIfAbsent(a.geo().countryCode(), k -> new long[3]);
            c[0]++;
            c[1] += a.failures();
            c[2] += a.successes();
            names.putIfAbsent(a.geo().countryCode(), a.geo().country());
        }
        List<MapCountry> countries = byCountry.entrySet().stream()
                .map(e -> new MapCountry(e.getKey(), names.get(e.getKey()), (int) e.getValue()[0], e.getValue()[1], e.getValue()[2]))
                .sorted(Comparator.comparingLong(MapCountry::failures).reversed())
                .toList();
        return new AttackMap(h, geo.enabled(), geo.pending(), servers, attackers, countries);
    }

    /** Sets (or clears, with an empty ip) the public address used to place a server on the map. */
    @PutMapping("/hosts/{id}/location")
    @Transactional
    public MapServer setLocation(@PathVariable String id, @RequestBody LocationChange change) {
        Host host = hosts.findById(id).orElseThrow(() -> new IllegalArgumentException("servidor não encontrado: " + id));
        String ip = change == null || change.ip() == null ? "" : change.ip().trim();
        if (ip.isEmpty()) {
            host.setManualIp(null);
        } else if (IpClassifier.kind(ip) != IpClassifier.Kind.PUBLIC) {
            throw new IllegalArgumentException("Use o IP público do servidor (o que aparece no painel da hospedagem), não um IP de rede privada ou do Tailscale.");
        } else {
            host.setManualIp(ip);
        }
        var r = locations.resolve(host);
        String loc = r.ip();
        IpGeo g = loc == null ? null : geo.locate(List.of(loc)).get(loc);
        return new MapServer(host.getId(), host.getStatus(), loc, r.source(),
                loc != null && IpClassifier.kind(loc) == IpClassifier.Kind.PUBLIC, GeoView.of(g));
    }
}
