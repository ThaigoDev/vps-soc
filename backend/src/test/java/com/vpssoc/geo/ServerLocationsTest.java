package com.vpssoc.geo;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServerLocationsTest {

    @Test
    void singleIpAppliesToEveryHost() {
        var l = new ServerLocations("82.25.79.73");
        assertThat(l.resolve(new com.vpssoc.domain.Host("srv731680", java.time.Instant.EPOCH)))
                .isEqualTo(new ServerLocations.Resolved("82.25.79.73", "ENV"));
    }

    @Test
    void perHostMappingAndFallbackToConnection() {
        var l = new ServerLocations("srv731680=82.25.79.73, web2=8.8.8.8");
        assertThat(l.resolve(new com.vpssoc.domain.Host("web2", java.time.Instant.EPOCH)).ip()).isEqualTo("8.8.8.8");
        assertThat(l.resolve(new com.vpssoc.domain.Host("other", java.time.Instant.EPOCH)).source()).isEqualTo("CONNECTION");
    }

    @Test
    void emptyConfigIsFineAndPrivateIpIsRejected() {
        assertThat(new ServerLocations("").resolve(new com.vpssoc.domain.Host("x", java.time.Instant.EPOCH)).source()).isEqualTo("CONNECTION");
        assertThatThrownBy(() -> new ServerLocations("100.105.113.27")).isInstanceOf(IllegalArgumentException.class);
    }
}
