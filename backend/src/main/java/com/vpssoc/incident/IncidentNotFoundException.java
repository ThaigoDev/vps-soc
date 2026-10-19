package com.vpssoc.incident;

public class IncidentNotFoundException extends RuntimeException {

    public IncidentNotFoundException(long id) {
        super("incident #" + id + " not found");
    }
}
