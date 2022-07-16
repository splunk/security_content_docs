---
title: "Windows Rasautou DLL Execution"
excerpt: "Dynamic-link Library Injection, System Binary Proxy Execution, Process Injection"
categories:
  - Endpoint
last_modified_at: 2022-02-15
toc: true
toc_label: ""
tags:
  - Dynamic-link Library Injection
  - Defense Evasion
  - Privilege Escalation
  - System Binary Proxy Execution
  - Defense Evasion
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the Windows Windows Remote Auto Dialer, rasautou.exe executing an arbitrary DLL. This technique is used to execute arbitrary shellcode or DLLs via the rasautou.exe LOLBin capability. During triage, review parent and child process behavior including file and image loads.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-15
- **Author**: Michael Haag, Splunk
- **ID**: 6f42b8ce-1e15-11ec-ad5a-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | Defense Evasion, Privilege Escalation |

| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | Defense Evasion |

| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND process_name="rasautou.exe" AND (like (cmd_line, "%-d %") AND like (cmd_line, "%-p %")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
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
False positives will be limited to applications that require Rasautou.exe to load a DLL from disk. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ attempting to load a DLL in a suspicious manner. |




#### Reference

* [https://github.com/mandiant/DueDLLigence](https://github.com/mandiant/DueDLLigence)
* [https://github.com/MHaggis/notes/blob/master/utilities/Invoke-SPLDLLigence.ps1](https://github.com/MHaggis/notes/blob/master/utilities/Invoke-SPLDLLigence.ps1)
* [https://gist.github.com/NickTyrer/c6043e4b302d5424f701f15baf136513](https://gist.github.com/NickTyrer/c6043e4b302d5424f701f15baf136513)
* [https://www.mandiant.com/resources/staying-hidden-on-the-endpoint-evading-detection-with-shellcode](https://www.mandiant.com/resources/staying-hidden-on-the-endpoint-evading-detection-with-shellcode)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055.001/rasautou/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055.001/rasautou/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_rasautou_dll_execution.yml) \| *version*: **1**