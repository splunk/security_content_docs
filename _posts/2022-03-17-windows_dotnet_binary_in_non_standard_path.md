---
title: "Windows DotNet Binary in Non Standard Path"
excerpt: "Masquerading, Rename System Utilities, System Binary Proxy Execution, InstallUtil"
categories:
  - Endpoint
last_modified_at: 2022-03-17
toc: true
toc_label: ""
tags:
  - Masquerading
  - Defense Evasion
  - Rename System Utilities
  - Defense Evasion
  - System Binary Proxy Execution
  - Defense Evasion
  - InstallUtil
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies native .net binaries within the Windows operating system that may be abused by adversaries by moving it to a new directory. The analytic identifies the .net binary by using a list. If one or the other matches an alert will be generated. Adversaries abuse these binaries as they are native to Windows and native DotNet. Note that not all SDK (post install of Windows) are captured in the list. Lookup - https://github.com/splunk/security_content/blob/develop/lookups/is_net_windows_file.csv.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-03-17
- **Author**: Michael Haag, Splunk
- **ID**: 21179107-099a-324a-94d3-08301e6c065f

### Annotations
<details>
  <summary>ATT&CK</summary>

<div markdown="1">

#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |

| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | Defense Evasion |

| [T1218.004](https://attack.mitre.org/techniques/T1218/004/) | InstallUtil | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.PT
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>


#### Search

```
 $ssa_input = 
| from read_ssa_enriched_events() 
| eval device=ucast(map_get(input_event, "dest_device_id"), "string", null), user=ucast(map_get(input_event, "dest_user_id"), "string", null), timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=lower(ucast(map_get(input_event, "process_path"), "string", null)), event_id=ucast(map_get(input_event, "event_id"), "string", null);
$cond_1 = 
| from $ssa_input 
| where process_name="msbuild.exe" OR process_name="comsvcconfig.exe" OR process_name="dfsradmin.exe" OR process_name="dfsvc.exe" OR process_name="microsoft.workflow.compiler.exe" OR process_name="smsvchost.exe" OR process_name="wsatconfig.exe" OR process_name="addinprocess.exe" OR process_name="addinprocess32.exe" OR process_name="addinutil.exe" OR process_name="aspnet_compiler.exe" OR process_name="aspnet_regbrowsers.exe" OR process_name="aspnet_regsql.exe" OR process_name="caspol.exe" OR process_name="datasvcutil.exe" OR process_name="edmgen.exe" OR process_name="installutil.exe" OR process_name="jsc.exe" OR process_name="ngentask.exe" OR process_name="regasm.exe" OR process_name="regsvcs.exe" OR process_name="sdnbr.exe" OR process_name="acu.exe" OR process_name="appvstreamingux.exe" OR process_name="dsac.exe" OR process_name="lbfoadmin.exe" OR process_name="microsoft.uev.synccontroller.exe" OR process_name="mtedit.exe" OR process_name="scriptrunner.exe" OR process_name="servermanager.exe" OR process_name="stordiag.exe" OR process_name="tzsync.exe" OR process_name="uevagentpolicygenerator.exe" OR process_name="uevappmonitor.exe" OR process_name="uevtemplatebaselinegenerator.exe" OR process_name="uevtemplateconfigitemgenerator.exe" OR process_name="powershell_ise.exe" OR process_name="iediagcmd.exe" OR process_name="xbox.tcui.exe" OR process_name="microsoft.activedirectory.webservices.exe" OR process_name="iisual.exe" OR process_name="filehistory.exe" OR process_name="secureassessmentbrowser.exe";

| from $cond_1 
| where match_regex(process_path, /(?i)\\windows\\system32/)=false AND match_regex(process_path, /(?i)\\windows\\syswow64/)=false AND match_regex(process_path, /(?i)\\windows\\adws/)=false AND match_regex(process_path, /(?i)\\windows\\networkcontroller/)=false AND match_regex(process_path, /(?i)\\windows\\systemapps/)=false AND match_regex(process_path, /(?i)\\winsxs/)=false AND match_regex(process_path, /(?i)\\microsoft.net/)=false 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(device, user), body=create_map(["event_id", event_id, "process_path", process_path, "process_name", process_name]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

> :information_source:
> **windows_dotnet_binary_in_non_standard_path_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.



#### Required fields
List of fields required to use this analytic.
* dest_device_id
* process_name
* _time
* dest_user_id
* process_path
* cmd_line



#### How To Implement
Collect endpoint data such as sysmon or 4688 events.
#### Known False Positives
False positives may be present and filtering may be required. Certain utilities will run from non-standard paths based on the third-party application in use.

#### Associated Analytic Story
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)
* [Unusual Processes](/stories/unusual_processes)
* [Ransomware](/stories/ransomware)
* [Signed Binary Proxy Execution InstallUtil](/stories/signed_binary_proxy_execution_installutil)
* [WhisperGate](/stories/whispergate)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | A system process $process_name$ with commandline $cmd_line$ spawn in non-default folder path on host $dest_device_id$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author.


#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.yaml)
* [https://attack.mitre.org/techniques/T1036/003/](https://attack.mitre.org/techniques/T1036/003/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/system_process_running_unexpected_location/dotnet_lolbin-windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/system_process_running_unexpected_location/dotnet_lolbin-windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_dotnet_binary_in_non_standard_path.yml) \| *version*: **1**