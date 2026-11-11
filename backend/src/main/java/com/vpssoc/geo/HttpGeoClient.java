package com.vpssoc.geo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.Optional;

/**
 * Free IP geolocation over HTTP, no key needed. Defaults to ipwho.is; also understands
 * ip-api.com's JSON (SOC_GEOIP_URL=http://ip-api.com/json/{ip}). Only the IP is sent.
 */
@Component
public class HttpGeoClient implements GeoClient {

    private final RestClient http;
    private final String urlTemplate;

    public HttpGeoClient(RestClient.Builder builder, @Value("${soc.geoip.url:https://ipwho.is/{ip}}") String urlTemplate) {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(4_000);
        factory.setReadTimeout(6_000);
        this.http = builder.requestFactory(factory).build();
        this.urlTemplate = urlTemplate;
    }

    @Override
    public Optional<Location> locate(String ip) {
        Map<String, Object> r = http.get().uri(urlTemplate, Map.of("ip", ip)).retrieve()
                .body(new ParameterizedTypeReference<Map<String, Object>>() {
                });
        return parse(r);
    }

    static Optional<Location> parse(Map<String, Object> r) {
        if (r == null || Boolean.FALSE.equals(r.get("success")) || "fail".equals(r.get("status"))) {
            return Optional.empty();
        }
        Double lat = number(r.getOrDefault("latitude", r.get("lat")));
        Double lon = number(r.getOrDefault("longitude", r.get("lon")));
        if (lat == null || lon == null) {
            return Optional.empty();
        }
        String org = null;
        if (r.get("connection") instanceof Map<?, ?> c) {
            org = text(c.get("org") != null ? c.get("org") : c.get("isp"));
        }
        if (org == null) {
            org = text(r.get("org") != null ? r.get("org") : r.get("isp"));
        }
        return Optional.of(new Location(text(r.get("country")),
                text(r.getOrDefault("country_code", r.get("countryCode"))),
                text(r.getOrDefault("region", r.get("regionName"))), text(r.get("city")), lat, lon, org));
    }

    private static Double number(Object o) {
        if (o instanceof Number n) {
            return n.doubleValue();
        }
        try {
            return o == null ? null : Double.parseDouble(o.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String text(Object o) {
        return o == null || o.toString().isBlank() ? null : o.toString();
    }
}
