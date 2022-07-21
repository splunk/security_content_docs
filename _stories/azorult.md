---
title: "Azorult"
last_modified_at: 2022-06-09
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Azorult malware including firewall modification, icacl execution, spawning more process, botnet c2 communication, defense evasion and etc. The AZORULT malware was first discovered in 2016 to be an information stealer that steals browsing history, cookies, ID/passwords, cryptocurrency information and more. It can also be a downloader of other malware. A variant of this malware was able to create a new, hidden administrator account on the machine to set a registry key to establish a Remote Desktop Protocol (RDP) connection. Exploit kits such as Fallout Exploit Kit (EK) and phishing mails with social engineering technique are one of the major infection vectors of the AZORult malware. The current malspam and phishing emails use fake product order requests, invoice documents and payment information requests. This Trojan-Spyware connects to command and control (C&C) servers of attacker to send and receive information.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-09
- **Author**: Teoderick Contreras, Splunk
- **ID**: efed5343-4ac2-42b1-a16d-da2428d0ce94

#### Narrative

Adversaries may use this technique to maximize the impact on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Operation with Consent Admin](/endpoint/allow_operation_with_consent_admin/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempt To Stop Security Service](/endpoint/attempt_to_stop_security_service/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CHCP Command Execution](/endpoint/chcp_command_execution/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Create local admin accounts using net exe](/endpoint/create_local_admin_accounts_using_net_exe/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Use of cmd exe to Launch Script Interpreters](/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender BlockAtFirstSeen Feature](/endpoint/disable_defender_blockatfirstseen_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender Enhanced Notification](/endpoint/disable_defender_enhanced_notification/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender Spynet Reporting](/endpoint/disable_defender_spynet_reporting/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender Submit Samples Consent Feature](/endpoint/disable_defender_submit_samples_consent_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Show Hidden Files](/endpoint/disable_show_hidden_files/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Hide Artifacts](/tags/#hide-artifacts), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Attempt To Disable Services](/endpoint/excessive_attempt_to_disable_services/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Cacls App](/endpoint/excessive_usage_of_cacls_app/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Net App](/endpoint/excessive_usage_of_net_app/) | [Account Access Removal](/tags/#account-access-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of SC Service Utility](/endpoint/excessive_usage_of_sc_service_utility/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Taskkill](/endpoint/excessive_usage_of_taskkill/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Firewall Allowed Program Enable](/endpoint/firewall_allowed_program_enable/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hide User Account From Sign-In Screen](/endpoint/hide_user_account_from_sign-in_screen/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Icacls Deny Command](/endpoint/icacls_deny_command/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Net Localgroup Discovery](/endpoint/net_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Net](/endpoint/network_connection_discovery_with_net/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/non_firefox_process_access_firefox_profile_dir/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Processes launching netsh](/endpoint/processes_launching_netsh/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender Exclusion Registry Entry](/endpoint/windows_defender_exclusion_registry_entry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://success.trendmicro.com/dcx/s/solution/000146108-azorult-malware-information?language=en_US&sfdcIFrameOrigin=null](https://success.trendmicro.com/dcx/s/solution/000146108-azorult-malware-information?language=en_US&sfdcIFrameOrigin=null)
* [https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/](https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/azorult.yml) \| *version*: **1**