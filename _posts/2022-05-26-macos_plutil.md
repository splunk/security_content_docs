---
title: "MacOS plutil"
excerpt: "Plist File Modification"
categories:
  - Endpoint
last_modified_at: 2022-05-26
toc: true
toc_label: ""
tags:
  - Plist File Modification
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect usage of plutil to modify plist files. Adversaries can modiy plist files to executed binaries or add command line arguments. Plist files in auto-run locations are executed upon user logon or system startup.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-05-26
- **Author**: Patrick Bareiss, Splunk
- **ID**: c11f2b57-92c1-4cd2-b46c-064eafb833ac


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1647](https://attack.mitre.org/techniques/T1647/) | Plist File Modification | Defense Evasion |

#### Search

```
`osquery` name=es_process_events columns.path=/usr/bin/plutil 
| rename columns.* as * 
| stats count  min(_time) as firstTime max(_time) as lastTime by username host cmdline pid path parent signing_id 
| rename username as User, cmdline as process, path as process_path 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `macos_plutil_filter`
```

#### Associated Analytic Story
* [Living Off The Land](/stories/living_off_the_land)


#### How To Implement
This detection uses osquery and endpoint security on MacOS. Follow the link in references, which describes how to setup process auditing in MacOS with endpoint security and osquery.

#### Required field
* _time
* columns.cmdline
* columns.pid
* columns.parent
* columns.path
* columns.signing_id
* columns.username
* host


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Administrators using plutil to change plist files.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | plutil are executed on $host$ from $user$ |




#### Reference

* [https://osquery.readthedocs.io/en/stable/deployment/process-auditing/](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1647/atomic_red_team/osquery.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1647/atomic_red_team/osquery.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/macos_plutil.yml) \| *version*: **2**