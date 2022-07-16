---
title: "Splunk User Enumeration Attempt"
excerpt: "Valid Accounts"
categories:
  - Application
last_modified_at: 2022-04-29
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-33845
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

On May 3rd, 2022, Splunk published a security advisory for  username enumeration stemming from verbose login failure messages present on some REST endpoints. This detection will alert on attempted exploitation in patched versions of Splunk as well as actual exploitation in unpatched version of Splunk.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-04-29
- **Author**: Lou Stella, Splunk
- **ID**: 25625cb4-1c4d-4463-b0f9-7cb462699cde


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
 `splunkd_failed_auths` 
| stats count(user) as auths by user, src 
| where auths>5 
| stats values(user) as "Users", sum(auths) as TotalFailedAuths by src 
| `splunk_user_enumeration_attempt_filter`
```

#### Associated Analytic Story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)


#### How To Implement
This detection does not require you to ingest any new data. The detection does require the ability to search the _audit index. This detection may assist in efforts to find password spraying or brute force authorization attempts in addition to someone enumerating usernames.

#### Required field
* user
* src
* info
* action


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Automation executing authentication attempts against your Splunk infrastructure with outdated credentials may cause false positives.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | $TotalFailedAuths$ failed authentication events to Splunk from $src$ detected. |



#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-33845](https://nvd.nist.gov/vuln/detail/CVE-2021-33845) | The Splunk Enterprise REST API allows enumeration of usernames via the lockout error message. The potential vulnerability impacts Splunk Enterprise instances before 8.1.7 when configured to repress verbose login errors. | 5.0 |



#### Reference

* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0502.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0502.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/splunkd_auth/audittrail.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/splunkd_auth/audittrail.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_user_enumeration_attempt.yml) \| *version*: **1**