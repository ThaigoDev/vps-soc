package com.vpssoc.domain;

import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

public enum EventType {
    SSH_FAILED_LOGIN(Severity.LOW, Category.AUTH_FAILURE),
    SSH_INVALID_USER(Severity.LOW, Category.AUTH_FAILURE),
    SSH_LOGIN_SUCCESS(Severity.INFO, Category.AUTH_SUCCESS),
    SUDO_COMMAND(Severity.INFO, Category.PRIVILEGE),
    SUDO_AUTH_FAILURE(Severity.MEDIUM, Category.PRIVILEGE),
    SUDO_DENIED(Severity.MEDIUM, Category.PRIVILEGE),
    PORT_OPENED(Severity.MEDIUM, Category.NETWORK),
    PORT_CLOSED(Severity.INFO, Category.NETWORK),
    PORT_BASELINE(Severity.INFO, Category.NETWORK),
    AGENT_STARTED(Severity.INFO, Category.AGENT),
    FILE_CREATED(Severity.MEDIUM, Category.FILE),
    FILE_MODIFIED(Severity.MEDIUM, Category.FILE),
    FILE_DELETED(Severity.MEDIUM, Category.FILE),
    FILE_BASELINE(Severity.INFO, Category.FILE),
    PROCESS_SUSPICIOUS(Severity.HIGH, Category.PROCESS);

    public enum Category { AUTH_FAILURE, AUTH_SUCCESS, PRIVILEGE, NETWORK, AGENT, FILE, PROCESS }

    public static final Set<EventType> SSH_FAILURES = EnumSet.of(SSH_FAILED_LOGIN, SSH_INVALID_USER);
    public static final Set<EventType> FILE_CHANGES = EnumSet.of(FILE_CREATED, FILE_MODIFIED, FILE_DELETED);

    private final Severity defaultSeverity;
    private final Category category;

    EventType(Severity defaultSeverity, Category category) {
        this.defaultSeverity = defaultSeverity;
        this.category = category;
    }

    public Severity defaultSeverity() {
        return defaultSeverity;
    }

    public Category category() {
        return category;
    }

    public static Optional<EventType> parse(String value) {
        try {
            return Optional.of(valueOf(value));
        } catch (IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }
}
