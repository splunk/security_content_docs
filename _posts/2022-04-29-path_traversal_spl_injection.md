---
title: "Path traversal SPL injection"
excerpt: "File and Directory Discovery"
categories:
  - Application
last_modified_at: 2022-04-29
toc: true
toc_label: ""
tags:
  - File and Directory Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-26889
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

On May 3rd, 2022, Splunk published a security advisory for a Path traversal in search parameter that can potentiall allow SPL injection. An attacker can cause the application to load data from incorrect endpoints, urls leading to outcomes such as running arbitrary SPL queries.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-04-29
- **Author**: Rod Soto, Splunk
- **ID**: dfe55688-82ed-4d24-a21b-ed8f0e0fda99


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Discovery |

#### Search

```
 `path_traversal_spl_injection` 
| search "\/..\/..\/..\/..\/..\/..\/..\/..\/..\/"  
| stats count by status clientip method uri_path uri_query 
| `path_traversal_spl_injection_filter`
```

#### Associated Analytic Story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)


#### How To Implement
This detection does not require you to ingest any new data. The detection does require the ability to search the _internal index. This search will provide search UI requests with path traversal parameter (&#34;../../../../../../../../../&#34;) which shows exploitation attempts.

#### Required field
* status
* clientip
* method
* uri_path
* uri_query


#### Kill Chain Phase
* Exploitation


#### Known False Positives
This search may find additional path traversal exploitation attempts.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | Path traversal exploitation attempt from $clientip$ |



#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2022-26889](https://nvd.nist.gov/vuln/detail/CVE-2022-26889) | In Splunk Enterprise versions before 8.1.2, the uri path to load a relative resource within a web page is vulnerable to path traversal. It allows an attacker to potentially inject arbitrary content into the web page (e.g., HTML Injection, XSS) or bypass SPL safeguards for risky commands. The attack is browser-based. An attacker cannot exploit the attack at will and requires the attacker to initiate a request within the victim&#39;s browser (e.g., phishing). | 5.1 |



#### Reference

* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0506.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0506.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1083/splunk/path_traversal_spl_injection.txt](https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1083/splunk/path_traversal_spl_injection.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/path_traversal_spl_injection.yml) \| *version*: **1**