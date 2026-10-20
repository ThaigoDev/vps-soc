package com.vpssoc.response;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Classifies addresses and holds the never-block list. Mirrors the agent's built-in
 * protected ranges (the agent re-checks; this side avoids proposing pointless actions).
 */
public final class IpClassifier {

    public enum Kind { LOOPBACK, PRIVATE, TAILSCALE, LINK_LOCAL, PUBLIC, INVALID }

    private static final Pattern LITERAL = Pattern.compile("[0-9A-Fa-f:.]{2,45}");

    private record Cidr(byte[] net, int bits, String text) {
        boolean contains(byte[] addr) {
            if (addr.length != net.length) {
                return false;
            }
            int full = bits / 8, rest = bits % 8;
            for (int i = 0; i < full; i++) {
                if (addr[i] != net[i]) {
                    return false;
                }
            }
            if (rest == 0) {
                return true;
            }
            int mask = 0xff << (8 - rest) & 0xff;
            return (addr[full] & mask) == (net[full] & mask);
        }
    }

    private final List<Cidr> protectedRanges = new ArrayList<>();

    public IpClassifier(List<String> extra) {
        for (String c : List.of("0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "100.64.0.0/10", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")) {
            protectedRanges.add(parse(c));
        }
        if (extra != null) {
            for (String e : extra) {
                if (e != null && !e.isBlank()) {
                    protectedRanges.add(parse(e.trim()));
                }
            }
        }
    }

    /** The range that protects ip from blocking, or null when it may be blocked. */
    public String protectedBy(String ip) {
        byte[] a = bytes(ip);
        if (a == null) {
            return "endereço inválido";
        }
        for (Cidr c : protectedRanges) {
            if (c.contains(a)) {
                return c.text();
            }
        }
        return null;
    }

    public static Kind kind(String ip) {
        byte[] a = bytes(ip);
        if (a == null) {
            return Kind.INVALID;
        }
        if (a.length == 4) {
            int b0 = a[0] & 0xff, b1 = a[1] & 0xff;
            if (b0 == 127) return Kind.LOOPBACK;
            if (b0 == 10 || (b0 == 172 && b1 >= 16 && b1 <= 31) || (b0 == 192 && b1 == 168)) return Kind.PRIVATE;
            if (b0 == 100 && b1 >= 64 && b1 <= 127) return Kind.TAILSCALE;
            if (b0 == 169 && b1 == 254) return Kind.LINK_LOCAL;
            return Kind.PUBLIC;
        }
        if (isZeroExceptLast(a)) return Kind.LOOPBACK;
        int b0 = a[0] & 0xff;
        if ((b0 & 0xfe) == 0xfc) return Kind.PRIVATE;
        if (b0 == 0xfe && (a[1] & 0xc0) == 0x80) return Kind.LINK_LOCAL;
        return Kind.PUBLIC;
    }

    public static String kindLabel(Kind k) {
        return switch (k) {
            case LOOPBACK -> "Loopback (a própria máquina)";
            case PRIVATE -> "Rede privada";
            case TAILSCALE -> "Tailscale / CGNAT (sua rede privada)";
            case LINK_LOCAL -> "Link-local (ex.: terminal web do painel da Hostinger)";
            case PUBLIC -> "Internet pública";
            case INVALID -> "Inválido";
        };
    }

    private static boolean isZeroExceptLast(byte[] a) {
        for (int i = 0; i < a.length - 1; i++) {
            if (a[i] != 0) {
                return false;
            }
        }
        return a[a.length - 1] == 1;
    }

    private static Cidr parse(String c) {
        String[] parts = c.split("/");
        byte[] net = bytes(parts[0]);
        if (net == null) {
            throw new IllegalArgumentException("invalid IP/CIDR in allowlist: " + c);
        }
        int bits = parts.length > 1 ? Integer.parseInt(parts[1]) : net.length * 8;
        return new Cidr(net, bits, net.length == 4 && bits == 32 || net.length == 16 && bits == 128 ? parts[0] : c);
    }

    /** Parses only IP literals: InetAddress.getByName would otherwise do a DNS lookup. */
    private static byte[] bytes(String ip) {
        if (ip == null || !LITERAL.matcher(ip).matches()) {
            return null;
        }
        try {
            return InetAddress.getByName(ip).getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
