---
title: "Windows System File on Disk"
excerpt: "Exploitation for Privilege Escalation"
categories:
  - Endpoint
last_modified_at: 2022-05-16
toc: true
toc_label: ""
tags:
  - Exploitation for Privilege Escalation
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic will assist with identifying new .sys files introduced in the environment. This query is meant to identify sys file creates on disk. There will be noise, but reducing common process names or applications should help to limit any volume. The idea is to identify new sys files written to disk and identify them before they&#39;re added as a new kernel mode driver.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-05-16
- **Author**: Michael Haag, Splunk
- **ID**: 993ce99d-9cdd-42c7-a2cf-733d5954e5a6


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name="*.sys*" by _time span=1h Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path Filesystem.file_hash 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `windows_system_file_on_disk_filter`
```

#### Associated Analytic Story
* [Windows Drivers](/stories/windows_drivers)


#### How To Implement
To successfully implement this search you need to be ingesting information on files from your endpoints into the `Endpoint` datamodel in the `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product. In addition, filtering may occur by adding NOT (Filesystem.file_path IN (&#34;*\\Windows\\*&#34;, &#34;*\\Program File*&#34;, &#34;*\\systemroot\\*&#34;,&#34;%SystemRoot%*&#34;, &#34;system32\*&#34;)). This will level out the noise generated to potentally lead to generating notables.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### Kill Chain Phase
* Delivery


#### Known False Positives
False positives will be present. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 10.0 | 20 | 50 | A new driver is present on $dest$. |




#### Reference

* [https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/](https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/sysmon_sys_filemod.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/sysmon_sys_filemod.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_system_file_on_disk.yml) \| *version*: **2**