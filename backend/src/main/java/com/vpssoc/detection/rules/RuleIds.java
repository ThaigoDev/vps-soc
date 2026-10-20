package com.vpssoc.detection.rules;

public final class RuleIds {

    public static final String SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE";
    public static final String SSH_COMPROMISE = "SSH_LOGIN_AFTER_BRUTE_FORCE";
    public static final String SSH_ROOT_LOGIN = "SSH_ROOT_LOGIN";
    public static final String SSH_NEW_SOURCE = "SSH_LOGIN_NEW_SOURCE";
    public static final String SUDO_FAILURE = "SUDO_FAILURE";
    public static final String NEW_LISTENING_PORT = "NEW_LISTENING_PORT";
    public static final String FIM_AUTHORIZED_KEYS = "FIM_AUTHORIZED_KEYS";
    public static final String FIM_SSHD_CONFIG = "FIM_SSHD_CONFIG";
    public static final String FIM_SUDOERS = "FIM_SUDOERS";
    public static final String FIM_CRON = "FIM_CRON";
    public static final String FIM_ACCOUNTS = "FIM_ACCOUNTS";
    public static final String SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS";
    public static final String WEB_SHELL = "WEB_SHELL";
    public static final String AGENT_OFFLINE = "AGENT_OFFLINE";
    public static final String DISK_USAGE_HIGH = "DISK_USAGE_HIGH";
    public static final String SERVICE_FAILED = "SERVICE_FAILED";
    public static final String SECURITY_UPDATES = "SECURITY_UPDATES";
    public static final String REBOOT_REQUIRED = "REBOOT_REQUIRED";
    public static final String SSH_WEAK_CONFIG = "SSH_WEAK_CONFIG";
    public static final String SERVICE_DOWN = "SERVICE_DOWN";
    public static final String SERVICE_CRASH_LOOP = "SERVICE_CRASH_LOOP";
    public static final String SERVICE_HIGH_MEMORY = "SERVICE_HIGH_MEMORY";

    private RuleIds() {
    }
}
