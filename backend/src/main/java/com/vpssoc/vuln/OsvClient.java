package com.vpssoc.vuln;

import java.util.List;
import java.util.Map;

/** The OSV.dev API (https://google.github.io/osv.dev/api/): free, no key, covers GitHub + npm advisories. */
public interface OsvClient {

    record PackageVersion(String name, String version) {
    }

    /** For each query, the ids of the advisories affecting that exact version. */
    List<List<String>> queryBatch(List<PackageVersion> queries);

    /** The full advisory record. */
    Map<String, Object> vulnerability(String id);
}
