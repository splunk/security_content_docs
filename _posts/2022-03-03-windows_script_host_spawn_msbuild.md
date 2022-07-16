---
title: "Windows Script Host Spawn MSBuild"
excerpt: "MSBuild, Trusted Developer Utilities Proxy Execution"
categories:
  - Endpoint
last_modified_at: 2022-03-03
toc: true
toc_label: ""
tags:
  - MSBuild
  - Defense Evasion
  - Trusted Developer Utilities Proxy Execution
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious child process of MSBuild spawned by Windows Script Host - cscript or wscript. This behavior or event are commonly seen and used by malware or adversaries to execute malicious msbuild process using malicious script in the compromised host. During triage, review parallel processes and identify any file modifications. MSBuild may load a script from the same path without having command-line arguments.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-03-03
- **Author**: Michael Haag, Splunk
- **ID**: 92886f1c-9b11-11ec-848a-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1127.001](https://attack.mitre.org/techniques/T1127/001/) | MSBuild | Defense Evasion |

| [T1127](https://attack.mitre.org/techniques/T1127/) | Trusted Developer Utilities Proxy Execution | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND parent_process_name IS NOT NULL 
| where (parent_process_name LIKE "%wscript.exe" OR parent_process_name LIKE "%cscript.exe%") AND process_name="msbuild.exe" 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Trusted Developer Utilities Proxy Execution MSBuild](/stories/trusted_developer_utilities_proxy_execution_msbuild)
* [Living Off The Land](/stories/living_off_the_land)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Required field
* _time
* dest_device_id
* process_name
* parent_process_name
* process_path
* dest_user_id
* process
* cmd_line


#### Kill Chain Phase
* Exploitation


#### Known False Positives
False positives should be limited as developers do not spawn MSBuild via a WSH.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$. |




#### Reference

* [https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/#](https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/#)
* [https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/TestHarnesses/T1127.001_MSBuild/InvokeMSBuild.ps1](https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/TestHarnesses/T1127.001_MSBuild/InvokeMSBuild.ps1)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127.001/msbuild-windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127.001/msbuild-windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_script_host_spawn_msbuild.yml) \| *version*: **1**