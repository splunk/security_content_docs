---
title: "Windows Root Domain linked policies Discovery"
excerpt: "Domain Account, Account Discovery"
categories:
  - Endpoint
last_modified_at: 2022-04-25
toc: true
toc_label: ""
tags:
  - Domain Account
  - Discovery
  - Account Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the `[Adsisearcher]` type accelerator being used to query Active Directory for domain groups. Red Teams and adversaries may leverage `[Adsisearcher]` to enumerate root domain linked policies for situational awareness and Active Directory Discovery.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-25
- **Author**: Teoderick Contreras, Splunk
- **ID**: 80ffaede-1f12-49d5-a86e-b4b599b68b3c


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Discovery |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

#### Search

```
`powershell` EventCode=4104 ScriptBlockText = "*[adsisearcher]*" ScriptBlockText = "*.SearchRooT*" ScriptBlockText = "*.gplink*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer user_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_root_domain_linked_policies_discovery_filter`
```

#### Associated Analytic Story
* [Industroyer2](/stories/industroyer2)
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
The following Hunting analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Required field
* _time
* EventCode
* ScriptBlockText
* Computer
* user_id


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Administrators or power users may use this command for troubleshooting.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | powershell process having commandline $Message$ for user enumeration |




#### Reference

* [https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/)
* [https://medium.com/@pentesttas/discover-hidden-gpo-s-on-active-directory-using-ps-adsi-a284b6814c81](https://medium.com/@pentesttas/discover-hidden-gpo-s-on-active-directory-using-ps-adsi-a284b6814c81)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/adsi_discovery/windows-powershell-xml1.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/adsi_discovery/windows-powershell-xml1.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_root_domain_linked_policies_discovery.yml) \| *version*: **1**