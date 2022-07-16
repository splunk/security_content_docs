---
title: "Windows Hidden Schedule Task Settings"
excerpt: "Scheduled Task/Job"
categories:
  - Endpoint
last_modified_at: 2022-04-26
toc: true
toc_label: ""
tags:
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following query utilizes Windows Security EventCode 4698, A scheduled task was created, to identify suspicious tasks registered on Windows either via schtasks.exe OR TaskService with a hidden settings that are unique entry of malware like industroyer2 or attack that uses lolbin to download other file or payload to the infected machine.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0b730470-5fe8-4b13-93a7-fe0ad014d0cc


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```
`wineventlog_security` EventCode=4698 
| xmlkv Message 
| search Hidden = true 
| stats count min(_time) as firstTime max(_time) as lastTime by  Task_Name, Command, Author, Hidden, dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_hidden_schedule_task_settings_filter`
```

#### Associated Analytic Story
* [Industroyer2](/stories/industroyer2)
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the task schedule (Exa. Security Log EventCode 4698) endpoints. Tune and filter known instances of Task schedule used in your environment.

#### Required field
* _time
* dest
* Task_Name
* Command
* Author
* Enabled
* Hidden
* Arguments


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A schedule task with hidden setting enable in host $dest$ |




#### Reference

* [https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/)
* [https://cert.gov.ua/article/39518](https://cert.gov.ua/article/39518)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/hidden_schedule_task/security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/hidden_schedule_task/security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_hidden_schedule_task_settings.yml) \| *version*: **1**