---
title: "Windows Computer Account Requesting Kerberos Ticket"
excerpt: "Steal or Forge Kerberos Tickets"
categories:
  - Endpoint
last_modified_at: 2022-04-27
toc: true
toc_label: ""
tags:
  - Steal or Forge Kerberos Tickets
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a ComputerAccount requesting a Kerberos Ticket. typically, a user account requests a Kerberos ticket. This behavior was identified with KrbUpRelay, but additional Kerberos attacks have exhibited similar behavior.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-27
- **Author**: Michael Haag, Splunk
- **ID**: fb3b2bb3-75a4-4279-848a-165b42624770


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

#### Search

```
`wineventlog_security`  EventCode=4768 Account_Name="*$"  src_ip!="::1" 
| stats  count min(_time) as firstTime max(_time) as lastTime by dest, subject, action, Supplied_Realm_Name, user, Account_Name, src_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_computer_account_requesting_kerberos_ticket_filter`
```

#### Associated Analytic Story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)
* [Local Privilege Escalation With KrbRelayUp](/stories/local_privilege_escalation_with_krbrelayup)


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 4768 EventCode enabled. The Windows TA is also required.

#### Required field
* _time
* dest
* subject
* action
* Supplied_Realm_Name
* user
* Account_Name
* src_ip


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
It is possible false positives will be present based on third party applications. Filtering may be needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | A Computer Account requested a Kerberos ticket on $dest$, possibly indicative of Kerberos relay attack. |




#### Reference

* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_computer_account_requesting_kerberos_ticket.yml) \| *version*: **1**