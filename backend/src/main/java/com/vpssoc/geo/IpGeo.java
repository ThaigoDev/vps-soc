package com.vpssoc.geo;

import jakarta.persistence.*;

import java.time.Instant;

/** Cached geolocation of one IP; {@code ok = false} remembers a failed lookup for a while. */
@Entity
@Table(name = "ip_geo")
public class IpGeo {

    @Id
    private String ip;
    private boolean ok;
    private String country;
    private String countryCode;
    private String region;
    private String city;
    private Double lat;
    private Double lon;
    private String org;
    private Instant fetchedAt;

    protected IpGeo() {
    }

    public IpGeo(String ip, GeoClient.Location loc, Instant fetchedAt) {
        this.ip = ip;
        this.fetchedAt = fetchedAt;
        this.ok = loc != null && loc.lat() != null && loc.lon() != null;
        if (loc != null) {
            this.country = cut(loc.country(), 100);
            this.countryCode = loc.countryCode() == null || loc.countryCode().length() != 2 ? null : loc.countryCode().toUpperCase();
            this.region = cut(loc.region(), 100);
            this.city = cut(loc.city(), 100);
            this.lat = loc.lat();
            this.lon = loc.lon();
            this.org = cut(loc.org(), 255);
        }
    }

    private static String cut(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }

    public String getIp() { return ip; }
    public boolean isOk() { return ok; }
    public String getCountry() { return country; }
    public String getCountryCode() { return countryCode; }
    public String getRegion() { return region; }
    public String getCity() { return city; }
    public Double getLat() { return lat; }
    public Double getLon() { return lon; }
    public String getOrg() { return org; }
    public Instant getFetchedAt() { return fetchedAt; }
}
