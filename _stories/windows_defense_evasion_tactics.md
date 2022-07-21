---
title: "Windows Defense Evasion Tactics"
last_modified_at: 2018-05-31
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Processes
  - Endpoint_Registry
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect tactics used by malware to evade defenses on Windows endpoints. A few of these include suspicious `reg.exe` processes, files hidden with `attrib.exe` and disabling user-account control, among many others 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses), [Endpoint_Registry](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointRegistry)
- **Last Updated**: 2018-05-31
- **Author**: David Dorsey, Splunk
- **ID**: 56e24a28-5003-4047-b2db-e8f3c4618064

#### Narrative

Defense evasion is a tactic--identified in the MITRE ATT&CK framework--that adversaries employ in a variety of ways to bypass or defeat defensive security measures. There are many techniques enumerated by the MITRE ATT&CK framework that are applicable in this context. This Analytic Story includes searches designed to identify the use of such techniques on Windows platforms.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Add or Set Windows Defender Exclusion](/endpoint/add_or_set_windows_defender_exclusion/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CSC Net On The Fly Compilation](/endpoint/csc_net_on_the_fly_compilation/) | [Compile After Delivery](/tags/#compile-after-delivery), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Registry Tool](/endpoint/disable_registry_tool/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Security Logs Using MiniNt Registry](/endpoint/disable_security_logs_using_minint_registry/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Show Hidden Files](/endpoint/disable_show_hidden_files/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Hide Artifacts](/tags/#hide-artifacts), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable UAC Remote Restriction](/endpoint/disable_uac_remote_restriction/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows SmartScreen Protection](/endpoint/disable_windows_smartscreen_protection/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling CMD Application](/endpoint/disabling_cmd_application/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling ControlPanel](/endpoint/disabling_controlpanel/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Firewall with Netsh](/endpoint/disabling_firewall_with_netsh/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling FolderOptions Windows Feature](/endpoint/disabling_folderoptions_windows_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling NoRun Windows App](/endpoint/disabling_norun_windows_app/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling SystemRestore In Registry](/endpoint/disabling_systemrestore_in_registry/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Task Manager](/endpoint/disabling_task_manager/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive number of service control start as disabled](/endpoint/excessive_number_of_service_control_start_as_disabled/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Firewall Allowed Program Enable](/endpoint/firewall_allowed_program_enable/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [FodHelper UAC Bypass](/endpoint/fodhelper_uac_bypass/) | [Modify Registry](/tags/#modify-registry), [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [NET Profiler UAC bypass](/endpoint/net_profiler_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Windows Defender Exclusion Commands](/endpoint/powershell_windows_defender_exclusion_commands/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SLUI RunAs Elevated](/endpoint/slui_runas_elevated/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SLUI Spawning a Process](/endpoint/slui_spawning_a_process/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sdclt UAC Bypass](/endpoint/sdclt_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SilentCleanup UAC Bypass](/endpoint/silentcleanup_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Process Running from Unexpected Location](/endpoint/system_process_running_from_unexpected_location/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [UAC Bypass MMC Load Unsigned Dll](/endpoint/uac_bypass_mmc_load_unsigned_dll/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Command and Scripting Interpreter Hunting Path Traversal](/endpoint/windows_command_and_scripting_interpreter_hunting_path_traversal/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Command and Scripting Interpreter Path Traversal Exec](/endpoint/windows_command_and_scripting_interpreter_path_traversal_exec/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DISM Remove Defender](/endpoint/windows_dism_remove_defender/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender Exclusion Registry Entry](/endpoint/windows_defender_exclusion_registry_entry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Change Password Through Registry](/endpoint/windows_disable_change_password_through_registry/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Lock Workstation Feature Through Registry](/endpoint/windows_disable_lock_workstation_feature_through_registry/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Notification Center](/endpoint/windows_disable_notification_center/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Windows Group Policy Features Through Registry](/endpoint/windows_disable_windows_group_policy_features_through_registry/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Event For Service Disabled](/endpoint/windows_event_for_service_disabled/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Eventvwr UAC Bypass](/endpoint/windows_eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Excessive Disabled Services Event](/endpoint/windows_excessive_disabled_services_event/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hide Notification Features Through Registry](/endpoint/windows_hide_notification_features_through_registry/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defense Delete Win Defender Context Menu](/endpoint/windows_impair_defense_delete_win_defender_context_menu/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defense Delete Win Defender Profile Registry](/endpoint/windows_impair_defense_delete_win_defender_profile_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defenses Disable Win Defender Auto Logging](/endpoint/windows_impair_defenses_disable_win_defender_auto_logging/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Show Compress Color And Info Tip Registry](/endpoint/windows_modify_show_compress_color_and_info_tip_registry/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process With NamedPipe CommandLine](/endpoint/windows_process_with_namedpipe_commandline/) | [Process Injection](/tags/#process-injection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rasautou DLL Execution](/endpoint/windows_rasautou_dll_execution/) | [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rasautou DLL Execution](/endpoint/windows_rasautou_dll_execution/) | [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows WSReset UAC Bypass](/endpoint/windows_wsreset_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Defense_Evasion](https://attack.mitre.org/wiki/Defense_Evasion)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_defense_evasion_tactics.yml) \| *version*: **1**