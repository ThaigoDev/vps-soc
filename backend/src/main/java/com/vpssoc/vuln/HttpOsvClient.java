package com.vpssoc.vuln;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class HttpOsvClient implements OsvClient {

    private final RestClient http;

    public HttpOsvClient(RestClient.Builder builder) {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(10_000);
        factory.setReadTimeout(30_000);
        this.http = builder.baseUrl("https://api.osv.dev").requestFactory(factory).build();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<List<String>> queryBatch(List<PackageVersion> queries) {
        List<Map<String, Object>> body = queries.stream()
                .map(q -> Map.<String, Object>of("package", Map.of("name", q.name(), "ecosystem", "npm"), "version", q.version()))
                .toList();
        Map<String, Object> res = http.post().uri("/v1/querybatch").contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("queries", body)).retrieve().body(new ParameterizedTypeReference<Map<String, Object>>() {
                });
        List<List<String>> out = new ArrayList<>();
        List<Map<String, Object>> results = res == null ? List.of() : (List<Map<String, Object>>) res.getOrDefault("results", List.of());
        for (Map<String, Object> r : results) {
            List<String> ids = new ArrayList<>();
            if (r.get("vulns") instanceof List<?> l) {
                for (Object v : l) {
                    if (v instanceof Map<?, ?> m && m.get("id") != null) {
                        ids.add(m.get("id").toString());
                    }
                }
            }
            out.add(ids);
        }
        return out;
    }

    @Override
    public Map<String, Object> vulnerability(String id) {
        return http.get().uri("/v1/vulns/{id}", id).retrieve().body(new ParameterizedTypeReference<Map<String, Object>>() {
        });
    }
}
