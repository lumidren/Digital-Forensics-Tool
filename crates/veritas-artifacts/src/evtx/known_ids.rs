//! Static enrichment table: (event id, channel or provider) -> (short name, description, category).
//!
//! `source` is matched case-insensitively against the record's provider name first, then its
//! channel. Provider-specific entries therefore win over channel-wide ones (Sysmon 1 vs
//! Kernel-General 1 in the System channel).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownId {
    pub id: u32,
    pub source: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
}

const fn k(id: u32, source: &'static str, name: &'static str, description: &'static str, category: &'static str) -> KnownId {
    KnownId { id, source, name, description, category }
}

const SEC: &str = "Security";
const SYS: &str = "System";
const SYSMON: &str = "Microsoft-Windows-Sysmon";
const PS: &str = "Microsoft-Windows-PowerShell";
const PSC: &str = "Windows PowerShell";
const TS: &str = "Microsoft-Windows-TaskScheduler";
const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
const RCM: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager";
const RDPCORE: &str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS";
const WMI: &str = "Microsoft-Windows-WMI-Activity";
const DEF: &str = "Microsoft-Windows-Windows Defender";
const BITS: &str = "Microsoft-Windows-Bits-Client";
const FW: &str = "Microsoft-Windows-Windows Firewall With Advanced Security";
const KG: &str = "Microsoft-Windows-Kernel-General";
const APP: &str = "Application";
const SMBC: &str = "Microsoft-Windows-SmbClient";
const SMBS: &str = "Microsoft-Windows-SMBServer";
const APPLOCKER: &str = "Microsoft-Windows-AppLocker";
const CI: &str = "Microsoft-Windows-CodeIntegrity";
const MIT: &str = "Microsoft-Windows-Security-Mitigations";
const PRINT: &str = "Microsoft-Windows-PrintService";
const NTLM: &str = "Microsoft-Windows-NTLM";
const KDC: &str = "Microsoft-Windows-Kerberos-Key-Distribution-Center";
const EVL: &str = "Microsoft-Windows-Eventlog";

pub static KNOWN_IDS: &[KnownId] = &[
    // Security auditing
    k(4624, SEC, "logon_success", "An account was successfully logged on", "logon"),
    k(4625, SEC, "logon_failure", "An account failed to log on", "logon"),
    k(4634, SEC, "logoff", "An account was logged off", "logon"),
    k(4647, SEC, "user_initiated_logoff", "User initiated logoff", "logon"),
    k(4648, SEC, "explicit_credential_logon", "A logon was attempted using explicit credentials", "logon"),
    k(4672, SEC, "special_privileges_logon", "Special privileges assigned to new logon", "logon"),
    k(4688, SEC, "process_created", "A new process has been created", "process"),
    k(4689, SEC, "process_exited", "A process has exited", "process"),
    k(4697, SEC, "service_installed", "A service was installed in the system", "service"),
    k(4698, SEC, "scheduled_task_created", "A scheduled task was created", "task"),
    k(4699, SEC, "scheduled_task_deleted", "A scheduled task was deleted", "task"),
    k(4700, SEC, "scheduled_task_enabled", "A scheduled task was enabled", "task"),
    k(4701, SEC, "scheduled_task_disabled", "A scheduled task was disabled", "task"),
    k(4702, SEC, "scheduled_task_updated", "A scheduled task was updated", "task"),
    k(4720, SEC, "user_account_created", "A user account was created", "account"),
    k(4722, SEC, "user_account_enabled", "A user account was enabled", "account"),
    k(4724, SEC, "password_reset_attempt", "An attempt was made to reset an account's password", "account"),
    k(4726, SEC, "user_account_deleted", "A user account was deleted", "account"),
    k(4728, SEC, "member_added_global_group", "A member was added to a security-enabled global group", "account"),
    k(4732, SEC, "member_added_local_group", "A member was added to a security-enabled local group", "account"),
    k(4735, SEC, "local_group_changed", "A security-enabled local group was changed", "account"),
    k(4738, SEC, "user_account_changed", "A user account was changed", "account"),
    k(4740, SEC, "user_account_locked_out", "A user account was locked out", "account"),
    k(4756, SEC, "member_added_universal_group", "A member was added to a security-enabled universal group", "account"),
    k(4768, SEC, "kerberos_tgt_requested", "A Kerberos authentication ticket (TGT) was requested", "authentication"),
    k(4769, SEC, "kerberos_service_ticket_requested", "A Kerberos service ticket was requested", "authentication"),
    k(4771, SEC, "kerberos_preauth_failed", "Kerberos pre-authentication failed", "authentication"),
    k(4776, SEC, "ntlm_credential_validation", "The computer attempted to validate the credentials for an account", "authentication"),
    k(4778, SEC, "session_reconnected", "A session was reconnected to a Window Station", "logon"),
    k(4779, SEC, "session_disconnected", "A session was disconnected from a Window Station", "logon"),
    k(4798, SEC, "local_group_membership_enumerated", "A user's local group membership was enumerated", "discovery"),
    k(4799, SEC, "security_group_membership_enumerated", "A security-enabled local group membership was enumerated", "discovery"),
    k(5140, SEC, "network_share_accessed", "A network share object was accessed", "file-share"),
    k(5145, SEC, "network_share_object_checked", "A network share object was checked for access", "file-share"),
    k(5156, SEC, "wfp_connection_allowed", "The Windows Filtering Platform has permitted a connection", "network"),
    k(5157, SEC, "wfp_connection_blocked", "The Windows Filtering Platform has blocked a connection", "network"),
    k(1102, SEC, "audit_log_cleared", "The audit log was cleared", "log-clear"),
    k(1100, SEC, "eventlog_service_shutdown", "The event logging service has shut down", "log-clear"),
    k(1104, SEC, "security_log_full", "The security log is now full", "log-clear"),
    k(4608, SEC, "windows_starting_up", "Windows is starting up", "system"),
    k(4616, SEC, "system_time_changed", "The system time was changed", "system"),
    k(4657, SEC, "registry_value_modified", "A registry value was modified", "registry"),
    k(4663, SEC, "object_access_attempt", "An attempt was made to access an object", "file"),
    k(4719, SEC, "audit_policy_changed", "System audit policy was changed", "defense-evasion"),
    k(4731, SEC, "local_group_created", "A security-enabled local group was created", "account"),
    k(4902, SEC, "per_user_audit_policy_table_created", "The Per-user audit policy table was created", "system"),
    k(4907, SEC, "auditing_settings_changed", "Auditing settings on object were changed", "defense-evasion"),
    // System channel
    k(7045, SYS, "service_installed", "A service was installed in the system", "service"),
    k(7034, SYS, "service_crashed", "A service terminated unexpectedly", "service"),
    k(7036, SYS, "service_state_changed", "A service entered the running or stopped state", "service"),
    k(7040, SYS, "service_start_type_changed", "The start type of a service was changed", "service"),
    k(7035, SYS, "service_control_sent", "A service control was sent", "service"),
    k(104, EVL, "log_cleared", "An event log was cleared", "log-clear"),
    k(104, SYS, "log_cleared", "An event log was cleared", "log-clear"),
    k(1102, EVL, "audit_log_cleared", "The audit log was cleared", "log-clear"),
    k(6005, SYS, "eventlog_started", "The Event log service was started", "system"),
    k(6006, SYS, "eventlog_stopped", "The Event log service was stopped", "system"),
    k(6008, SYS, "unexpected_shutdown", "The previous system shutdown was unexpected", "system"),
    k(6009, SYS, "os_version_at_boot", "Operating system version information at boot", "system"),
    k(6011, SYS, "computer_name_changed", "The NetBIOS name and DNS host name of this computer changed", "system"),
    k(6013, SYS, "system_uptime", "The system uptime", "system"),
    k(1074, SYS, "shutdown_initiated", "A process initiated a restart or shutdown", "system"),
    k(41, SYS, "kernel_power_unexpected_reboot", "The system rebooted without cleanly shutting down", "system"),
    k(10016, SYS, "dcom_permission_error", "DCOM application-specific permission settings error", "system"),
    k(4697, SYS, "service_installed", "A service was installed in the system", "service"),
    // Kernel-General (System channel provider)
    k(1, KG, "system_time_changed", "The system time has changed", "system"),
    k(12, KG, "os_started", "The operating system started", "system"),
    k(13, KG, "os_shutdown", "The operating system is shutting down", "system"),
    // Sysmon
    k(1, SYSMON, "sysmon_process_create", "Process creation", "sysmon"),
    k(2, SYSMON, "sysmon_file_time_changed", "A process changed a file creation time", "sysmon"),
    k(3, SYSMON, "sysmon_network_connection", "Network connection detected", "sysmon"),
    k(4, SYSMON, "sysmon_state_changed", "Sysmon service state changed", "sysmon"),
    k(5, SYSMON, "sysmon_process_terminated", "Process terminated", "sysmon"),
    k(6, SYSMON, "sysmon_driver_loaded", "Driver loaded", "sysmon"),
    k(7, SYSMON, "sysmon_image_loaded", "Image loaded", "sysmon"),
    k(8, SYSMON, "sysmon_create_remote_thread", "CreateRemoteThread detected", "sysmon"),
    k(9, SYSMON, "sysmon_raw_access_read", "RawAccessRead detected", "sysmon"),
    k(10, SYSMON, "sysmon_process_access", "Process accessed", "sysmon"),
    k(11, SYSMON, "sysmon_file_create", "File created", "sysmon"),
    k(12, SYSMON, "sysmon_registry_object", "Registry object added or deleted", "sysmon"),
    k(13, SYSMON, "sysmon_registry_value_set", "Registry value set", "sysmon"),
    k(14, SYSMON, "sysmon_registry_rename", "Registry object renamed", "sysmon"),
    k(15, SYSMON, "sysmon_file_stream_created", "File stream created", "sysmon"),
    k(16, SYSMON, "sysmon_config_changed", "Sysmon configuration change", "sysmon"),
    k(17, SYSMON, "sysmon_pipe_created", "Named pipe created", "sysmon"),
    k(18, SYSMON, "sysmon_pipe_connected", "Named pipe connected", "sysmon"),
    k(19, SYSMON, "sysmon_wmi_filter", "WmiEventFilter activity detected", "sysmon"),
    k(20, SYSMON, "sysmon_wmi_consumer", "WmiEventConsumer activity detected", "sysmon"),
    k(21, SYSMON, "sysmon_wmi_binding", "WmiEventConsumerToFilter activity detected", "sysmon"),
    k(22, SYSMON, "sysmon_dns_query", "DNS query", "sysmon"),
    k(23, SYSMON, "sysmon_file_delete_archived", "File delete archived", "sysmon"),
    k(24, SYSMON, "sysmon_clipboard_change", "Clipboard changed", "sysmon"),
    k(25, SYSMON, "sysmon_process_tampering", "Process image change", "sysmon"),
    k(26, SYSMON, "sysmon_file_delete_logged", "File delete logged", "sysmon"),
    k(27, SYSMON, "sysmon_file_block_executable", "File block executable", "sysmon"),
    k(28, SYSMON, "sysmon_file_block_shredding", "File block shredding", "sysmon"),
    k(29, SYSMON, "sysmon_file_executable_detected", "File executable detected", "sysmon"),
    // PowerShell
    k(400, PSC, "powershell_engine_started", "Engine state changed from None to Available", "powershell"),
    k(403, PSC, "powershell_engine_stopped", "Engine state changed from Available to Stopped", "powershell"),
    k(600, PSC, "powershell_provider_started", "Provider lifecycle: provider started", "powershell"),
    k(800, PSC, "powershell_pipeline_execution", "Pipeline execution details", "powershell"),
    k(4103, PS, "powershell_module_logging", "Module logging: pipeline execution", "powershell"),
    k(4104, PS, "powershell_script_block", "Script block logging", "powershell"),
    k(4105, PS, "powershell_script_block_start", "Script block invocation start", "powershell"),
    k(4106, PS, "powershell_script_block_stop", "Script block invocation stop", "powershell"),
    k(53504, PS, "powershell_ipc_listener", "PowerShell named pipe IPC listener started", "powershell"),
    k(40961, PS, "powershell_console_starting", "PowerShell console is starting up", "powershell"),
    k(40962, PS, "powershell_console_ready", "PowerShell console is ready for user input", "powershell"),
    // Task Scheduler
    k(106, TS, "task_registered", "Task registered", "task"),
    k(140, TS, "task_updated", "Task registration updated", "task"),
    k(141, TS, "task_deleted", "Task registration deleted", "task"),
    k(200, TS, "task_action_started", "Action started", "task"),
    k(201, TS, "task_action_completed", "Action completed", "task"),
    k(129, TS, "task_process_created", "Created task process", "task"),
    // RDP
    k(21, LSM, "rdp_session_logon", "Remote Desktop Services: Session logon succeeded", "rdp"),
    k(22, LSM, "rdp_shell_start", "Remote Desktop Services: Shell start notification received", "rdp"),
    k(23, LSM, "rdp_session_logoff", "Remote Desktop Services: Session logoff succeeded", "rdp"),
    k(24, LSM, "rdp_session_disconnected", "Remote Desktop Services: Session has been disconnected", "rdp"),
    k(25, LSM, "rdp_session_reconnected", "Remote Desktop Services: Session reconnection succeeded", "rdp"),
    k(39, LSM, "rdp_session_disconnected_by_other", "Session has been disconnected by another session", "rdp"),
    k(40, LSM, "rdp_session_disconnect_reason", "Session has been disconnected, reason code", "rdp"),
    k(1149, RCM, "rdp_user_authentication_succeeded", "Remote Desktop Services: User authentication succeeded", "rdp"),
    k(131, RDPCORE, "rdp_connection_accepted", "The server accepted a new TCP connection", "rdp"),
    k(98, RDPCORE, "rdp_connection_established", "A TCP connection has been successfully established", "rdp"),
    k(140, RDPCORE, "rdp_connection_failed_bad_credentials", "A connection failed because the user name or password is not correct", "rdp"),
    // WMI
    k(5857, WMI, "wmi_provider_started", "WMI provider started", "wmi"),
    k(5858, WMI, "wmi_query_error", "WMI query error", "wmi"),
    k(5859, WMI, "wmi_event_registration", "WMI event registration (subscription)", "wmi"),
    k(5860, WMI, "wmi_temporary_event_consumer", "Temporary WMI event consumer registered", "wmi"),
    k(5861, WMI, "wmi_permanent_event_consumer", "Permanent WMI event consumer binding", "wmi"),
    // Defender
    k(1006, DEF, "defender_malware_detected", "The antimalware engine found malware", "defender"),
    k(1007, DEF, "defender_action_taken", "The antimalware platform performed an action", "defender"),
    k(1008, DEF, "defender_action_failed", "The antimalware platform attempted an action and failed", "defender"),
    k(1015, DEF, "defender_suspicious_behavior", "The antimalware platform detected suspicious behavior", "defender"),
    k(1116, DEF, "defender_threat_detected", "The antimalware platform detected malware or unwanted software", "defender"),
    k(1117, DEF, "defender_threat_action_taken", "The antimalware platform performed an action to protect the system", "defender"),
    k(1118, DEF, "defender_threat_action_failed", "The antimalware platform attempted an action and failed", "defender"),
    k(1119, DEF, "defender_threat_action_critical_failure", "The antimalware platform encountered a critical error acting on malware", "defender"),
    k(5001, DEF, "defender_realtime_disabled", "Real-time protection was disabled", "defender"),
    k(5007, DEF, "defender_config_changed", "The antimalware platform configuration changed", "defender"),
    // BITS
    k(59, BITS, "bits_job_started", "BITS started a transfer job", "bits"),
    k(60, BITS, "bits_job_stopped", "BITS stopped transferring a job", "bits"),
    k(61, BITS, "bits_job_error", "BITS stopped transferring a job with an error", "bits"),
    // Firewall
    k(2004, FW, "firewall_rule_added", "A rule has been added to the Windows Firewall exception list", "firewall"),
    k(2005, FW, "firewall_rule_modified", "A rule has been modified in the Windows Firewall exception list", "firewall"),
    k(2006, FW, "firewall_rule_deleted", "A rule has been deleted in the Windows Firewall exception list", "firewall"),
    // Application
    k(1000, APP, "application_error", "Application error (crash)", "application"),
    k(1001, APP, "windows_error_reporting", "Windows Error Reporting fault bucket", "application"),
    k(1002, APP, "application_hang", "Application hang", "application"),
    // AppLocker
    k(8002, APPLOCKER, "applocker_exe_allowed", "EXE/DLL was allowed to run", "applocker"),
    k(8003, APPLOCKER, "applocker_exe_would_block", "EXE/DLL was allowed but would have been prevented (audit)", "applocker"),
    k(8004, APPLOCKER, "applocker_exe_blocked", "EXE/DLL was prevented from running", "applocker"),
    k(8005, APPLOCKER, "applocker_script_allowed", "Script/MSI was allowed to run", "applocker"),
    k(8006, APPLOCKER, "applocker_script_would_block", "Script/MSI was allowed but would have been prevented (audit)", "applocker"),
    k(8007, APPLOCKER, "applocker_script_blocked", "Script/MSI was prevented from running", "applocker"),
    // Code integrity / mitigations
    k(3077, CI, "code_integrity_blocked", "Code Integrity determined that a process attempted to load an unsigned/blocked image", "code-integrity"),
    k(3033, CI, "code_integrity_signing_level", "Code Integrity determined that a process attempted to load an image that did not meet signing requirements", "code-integrity"),
    k(10, MIT, "mitigation_audit", "Exploit protection mitigation audit", "mitigation"),
    k(11, MIT, "mitigation_blocked", "Exploit protection mitigation enforced", "mitigation"),
    // Print service
    k(307, PRINT, "document_printed", "A document was printed", "print"),
    k(316, PRINT, "printer_driver_added", "A printer driver was added or updated", "print"),
    // NTLM
    k(8001, NTLM, "ntlm_outgoing_auth", "NTLM client blocked audit: outgoing NTLM authentication", "authentication"),
    k(8002, NTLM, "ntlm_incoming_auth", "NTLM server blocked audit: incoming NTLM traffic", "authentication"),
    k(8003, NTLM, "ntlm_domain_auth", "NTLM server blocked in this domain audit", "authentication"),
    k(8004, NTLM, "ntlm_dc_pass_through", "Domain controller NTLM pass-through authentication audit", "authentication"),
    // Kerberos KDC
    k(4769, KDC, "kerberos_service_ticket_requested", "A Kerberos service ticket was requested", "authentication"),
];

/// SMB client/server operational IDs 1001-1020 share one description per provider.
pub static KNOWN_RANGES: &[(u32, u32, &str, &str, &str, &str)] = &[
    (1001, 1020, SMBC, "smb_client_event", "SMB client connectivity/authentication event", "smb"),
    (1001, 1020, SMBS, "smb_server_event", "SMB server connectivity/authentication event", "smb"),
];

/// Look up enrichment for an event.
pub fn lookup(event_id: u32, provider: &str, channel: &str) -> Option<KnownId> {
    let eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    let chan_base = channel.split('/').next().unwrap_or(channel);
    // 1. provider match
    if let Some(k) = KNOWN_IDS.iter().find(|k| k.id == event_id && (eq(k.source, provider) || (k.source.len() > 12 && provider.to_ascii_lowercase().starts_with(&k.source.to_ascii_lowercase())))) {
        return Some(*k);
    }
    for (lo, hi, src, name, desc, cat) in KNOWN_RANGES {
        if (*lo..=*hi).contains(&event_id) && (eq(src, provider) || eq(src, chan_base)) {
            return Some(KnownId { id: event_id, source: src, name, description: desc, category: cat });
        }
    }
    // 2. channel match (full channel, then the part before '/')
    KNOWN_IDS.iter().find(|k| k.id == event_id && (eq(k.source, channel) || eq(k.source, chan_base))).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_size_and_lookups() {
        assert!(KNOWN_IDS.len() >= 120, "{}", KNOWN_IDS.len());
        assert_eq!(lookup(4624, "Microsoft-Windows-Security-Auditing", "Security").unwrap().category, "logon");
        assert_eq!(lookup(1, "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational").unwrap().name, "sysmon_process_create");
        assert_eq!(lookup(1, "Microsoft-Windows-Kernel-General", "System").unwrap().name, "system_time_changed");
        assert_eq!(lookup(7045, "Service Control Manager", "System").unwrap().category, "service");
        assert_eq!(lookup(1010, "Microsoft-Windows-SmbClient", "Microsoft-Windows-SmbClient/Connectivity").unwrap().category, "smb");
        assert!(lookup(99999, "x", "y").is_none());
    }
}
