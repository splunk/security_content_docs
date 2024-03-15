---
title: "Windows User Execution Malicious URL Shortcut File"
excerpt: "Malicious File, User Execution"
categories:
  - Endpoint
last_modified_at: 2023-01-12
toc: true
toc_label: ""
tags:
  - Malicious File
  - Execution
  - User Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
redirect_from: endpoint/windows_user_execution_malicious_url_shortcut_file/
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify suspicious creation of URL shortcut link files. This technique was seen in CHAOS ransomware where it will drop this .url link file in %startup% folder that contains the path of its malicious dropped file to execute upon the reboot of the targeted host. The creation of this file can be created by a normal application or software but it is a good practice to verify this type of file specially the resource it tries to execute which is commonly a website.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-01-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 5c7ee6ad-baf4-44fb-b2f0-0cfeddf82dbc

### Annotations
<details>
  <summary>ATT&CK</summary>

<div markdown="1">

#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Execution |

| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Installation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 10



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>


#### Search

```

|tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where NOT(Filesystem.file_path IN ("*\\Program Files*")) Filesystem.file_name = *.url by Filesystem.file_create_time Filesystem.process_id  Filesystem.file_name Filesystem.user Filesystem.file_path Filesystem.process_guid Filesystem.dest 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_user_execution_malicious_url_shortcut_file_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_user_execution_malicious_url_shortcut_file_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.



#### Required fields
List of fields required to use this analytic.
* _time
* Filesystem.file_create_time
* Filesystem.process_id
* Filesystem.file_name
* Filesystem.user
* Filesystem.file_path
* Filesystem.process_guid
* Filesystem.dest



#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the Filesystem responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node.
#### Known False Positives
Administrators may allow creation of script or exe in this path.

#### Associated Analytic Story
* [Chaos Ransomware](/stories/chaos_ransomware)
* [NjRAT](/stories/njrat)
* [Snake Keylogger](/stories/snake_keylogger)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | a process created URL shortcut file in $file_path$ of $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author.


#### Reference

* [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)
* [https://www.fortinet.com/blog/threat-research/chaos-ransomware-variant-sides-with-russia](https://www.fortinet.com/blog/threat-research/chaos-ransomware-variant-sides-with-russia)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_user_execution_malicious_url_shortcut_file.yml) \| *version*: **1**