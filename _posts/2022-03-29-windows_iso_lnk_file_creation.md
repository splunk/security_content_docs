---
title: "Windows ISO LNK File Creation"
excerpt: "Spearphishing Attachment, Phishing, Malicious Link, User Execution"
categories:
  - Endpoint
last_modified_at: 2022-03-29
toc: true
toc_label: ""
tags:
  - Spearphishing Attachment
  - Initial Access
  - Phishing
  - Initial Access
  - Malicious Link
  - Execution
  - User Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of a delivered ISO file that has been mounted and the afformention lnk or file opened within it. When the ISO file is opened, the files are saved in the %USER%\AppData\Local\Temp\&lt;random folder name&gt;\ path. The analytic identifies .iso.lnk written to the path. The name of the ISO file is prepended.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-29
- **Author**: Michael Haag, Splunk
- **ID**: d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Malicious Link | Execution |

| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*\\Microsoft\\Windows\\Recent\\*") Filesystem.file_name IN ("*.iso.lnk") by Filesystem.file_create_time Filesystem.process_id Filesystem.file_name Filesystem.file_path Filesystem.dest 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_iso_lnk_file_creation_filter`
```

#### Associated Analytic Story
* [Spearphishing Attachments](/stories/spearphishing_attachments)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Required field
* Filesystem.file_create_time
* Filesystem.process_id
* Filesystem.file_name
* Filesystem.file_path
* Filesystem.dest


#### Kill Chain Phase
* Delivery


#### Known False Positives
False positives may be high depending on the environment and consistent use of ISOs mounting. Restrict to servers, or filter out based on commonly used ISO names. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 80 | 50 | An ISO file was mounted on $dest$ and should be reviewed and filtered as needed. |




#### Reference

* [https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/)
* [https://github.com/MHaggis/notes/blob/master/utilities/ISOBuilder.ps1](https://github.com/MHaggis/notes/blob/master/utilities/ISOBuilder.ps1)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.001/atomic_red_team/iso_windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.001/atomic_red_team/iso_windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_iso_lnk_file_creation.yml) \| *version*: **1**