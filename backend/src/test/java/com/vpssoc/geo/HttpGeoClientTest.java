package com.vpssoc.geo;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class HttpGeoClientTest {

    @Test
    void parsesIpwhoIs() {
        var loc = HttpGeoClient.parse(Map.of("success", true, "country", "Brazil", "country_code", "BR", "region", "Sao Paulo",
                "city", "São Paulo", "latitude", -23.55, "longitude", -46.63, "connection", Map.of("org", "Hostinger")));
        assertThat(loc).hasValueSatisfying(l -> {
            assertThat(l.countryCode()).isEqualTo("BR");
            assertThat(l.lat()).isEqualTo(-23.55);
            assertThat(l.org()).isEqualTo("Hostinger");
        });
    }

    @Test
    void parsesIpApi() {
        var loc = HttpGeoClient.parse(Map.of("status", "success", "country", "Germany", "countryCode", "DE",
                "regionName", "Hesse", "city", "Frankfurt", "lat", 50.11, "lon", 8.68, "isp", "Example GmbH"));
        assertThat(loc).hasValueSatisfying(l -> {
            assertThat(l.countryCode()).isEqualTo("DE");
            assertThat(l.region()).isEqualTo("Hesse");
            assertThat(l.org()).isEqualTo("Example GmbH");
        });
    }

    @Test
    void failureIsEmpty() {
        assertThat(HttpGeoClient.parse(Map.of("success", false, "message", "Reserved range"))).isEmpty();
        assertThat(HttpGeoClient.parse(Map.of("status", "fail"))).isEmpty();
        assertThat(HttpGeoClient.parse(null)).isEmpty();
    }
}
