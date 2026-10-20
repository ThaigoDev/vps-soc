package com.vpssoc.detection;

import java.util.Map;

import static java.util.Map.entry;

/** The MITRE ATT&CK techniques the built-in rules map to. */
public final class Mitre {

    public static final String BRUTE_FORCE = "T1110";
    public static final String PASSWORD_GUESSING = "T1110.001";
    public static final String PASSWORD_SPRAYING = "T1110.003";
    public static final String VALID_ACCOUNTS = "T1078";
    public static final String LOCAL_ACCOUNTS = "T1078.003";
    public static final String SUDO = "T1548.003";
    public static final String NON_STANDARD_PORT = "T1571";
    public static final String COMMAND_INTERPRETER = "T1059";
    public static final String UNIX_SHELL = "T1059.004";
    public static final String DISABLE_TOOLS = "T1562.001";
    public static final String ACCOUNT_MANIPULATION = "T1098";
    public static final String SSH_AUTHORIZED_KEYS = "T1098.004";
    public static final String CREATE_LOCAL_ACCOUNT = "T1136.001";
    public static final String CRON = "T1053.003";
    public static final String WEB_SHELL = "T1505.003";
    public static final String FILE_DELETION = "T1070.004";
    public static final String EXPLOIT_PUBLIC_APP = "T1190";

    private static final Map<String, String> NAMES = Map.ofEntries(
            entry(BRUTE_FORCE, "Brute Force"),
            entry(PASSWORD_GUESSING, "Brute Force: Password Guessing"),
            entry(PASSWORD_SPRAYING, "Brute Force: Password Spraying"),
            entry(VALID_ACCOUNTS, "Valid Accounts"),
            entry(LOCAL_ACCOUNTS, "Valid Accounts: Local Accounts"),
            entry(SUDO, "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
            entry(NON_STANDARD_PORT, "Non-Standard Port"),
            entry(COMMAND_INTERPRETER, "Command and Scripting Interpreter"),
            entry(UNIX_SHELL, "Command and Scripting Interpreter: Unix Shell"),
            entry(DISABLE_TOOLS, "Impair Defenses: Disable or Modify Tools"),
            entry(ACCOUNT_MANIPULATION, "Account Manipulation"),
            entry(SSH_AUTHORIZED_KEYS, "Account Manipulation: SSH Authorized Keys"),
            entry(CREATE_LOCAL_ACCOUNT, "Create Account: Local Account"),
            entry(CRON, "Scheduled Task/Job: Cron"),
            entry(WEB_SHELL, "Server Software Component: Web Shell"),
            entry(FILE_DELETION, "Indicator Removal: File Deletion"),
            entry(EXPLOIT_PUBLIC_APP, "Exploit Public-Facing Application"));

    private Mitre() {
    }

    public static String name(String id) {
        return NAMES.getOrDefault(id, id);
    }

    public static String url(String id) {
        return "https://attack.mitre.org/techniques/" + id.replace('.', '/') + "/";
    }
}
