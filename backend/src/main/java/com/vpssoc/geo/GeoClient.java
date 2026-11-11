package com.vpssoc.geo;

import java.util.Optional;

/** Looks up where an IP address is. */
public interface GeoClient {

    record Location(String country, String countryCode, String region, String city, Double lat, Double lon, String org) {
    }

    /** Empty when the service does not know the address; throws on network errors. */
    Optional<Location> locate(String ip);
}
