---
title: "ProxyShell ProxyNotShell Behavior Detected"
excerpt: "Exploit Public-Facing Application"
categories:
  - Web
last_modified_at: 2022-10-03
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Risk
redirect_from: web/proxyshell_proxynotshell_behavior_detected/
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following correlation will identify activity related to Windows Exchange being actively exploited by adversaries related to ProxyShell or ProxyNotShell. In addition, the analytic correlates post-exploitation Cobalt Strike analytic story. Common post-exploitation behavior has been seen in the wild includes adversaries running nltest, Cobalt Strike, Mimikatz and adding a new user. The correlation specifically looks for 5 distinct analyticstories to trigger. Modify or tune as needed for your organization. 5 analytics is an arbitrary number but was chosen to reduce the amount of noise but also require the 2 analytic stories or a ProxyShell and CobaltStrike to fire. Adversaries will exploit the vulnerable Exchange server, abuse SSRF, drop a web shell, utilize the PowerShell Exchange modules and begin post-exploitation.

- **Type**: [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2022-10-03
- **Author**: Michael Haag, Splunk
- **ID**: c32fab32-6aaf-492d-bfaf-acbed8e50cdf

### Annotations
<details>
  <summary>ATT&CK</summary>

<div markdown="1">

#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Delivery


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 13



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>


#### Search

```

| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime sum(All_Risk.calculated_risk_score) as risk_score, count(All_Risk.calculated_risk_score) as risk_event_count, values(All_Risk.annotations.mitre_attack.mitre_tactic_id) as annotations.mitre_attack.mitre_tactic_id, dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id_count, values(All_Risk.analyticstories) as analyticstories values(All_Risk.annotations.mitre_attack.mitre_technique_id) as annotations.mitre_attack.mitre_technique_id, dc(All_Risk.annotations.mitre_attack.mitre_technique_id) as mitre_technique_id_count, values(All_Risk.tag) as tag, values(source) as source, dc(source) as source_count dc(All_Risk.analyticstories) as dc_analyticstories from datamodel=Risk.All_Risk where All_Risk.analyticstories IN ("ProxyNotShell","ProxyShell") OR (All_Risk.analyticstories IN ("ProxyNotShell","ProxyShell") AND All_Risk.analyticstories="Cobalt Strike") All_Risk.risk_object_type="system" by _time span=1h All_Risk.risk_object All_Risk.risk_object_type 
| `drop_dm_object_name(All_Risk)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| where source_count >=5 
| `proxyshell_proxynotshell_behavior_detected_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **proxyshell_proxynotshell_behavior_detected_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.



#### Required fields
List of fields required to use this analytic.
* All_Risk.analyticstories
* All_Risk.risk_object_type
* All_Risk.risk_object
* All_Risk.annotations.mitre_attack.mitre_tactic
* source



#### How To Implement
To implement this correlation, you will need to enable ProxyShell, ProxyNotShell and Cobalt Strike analytic stories (the anaytics themselves) and ensure proper data is being collected for Web and Endpoint datamodels. Run the correlation rule seperately to validate it is not triggering too much or generating incorrectly. Validate by running ProxyShell POC code and Cobalt Strike behavior.
#### Known False Positives
False positives will be limited, however tune or modify the query as needed.

#### Associated Analytic Story
* [ProxyShell](/stories/proxyshell)
* [ProxyNotShell](/stories/proxynotshell)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | ProxyShell or ProxyNotShell activity has been identified on $risk_object$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author.


#### Reference

* [https://www.gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html](https://www.gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html)
* [https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/](https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/web/proxyshell_proxynotshell_behavior_detected.yml) \| *version*: **1**