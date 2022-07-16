---
title: "Splunk protocol impersonation weak encryption simplerequest"
excerpt: "Digital Certificates"
categories:
  - Application
last_modified_at: 2022-05-24
toc: true
toc_label: ""
tags:
  - Digital Certificates
  - Resource Development
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-32152
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

On Splunk version 9 on Python3 client libraries verify server certificates by default and use CA certificate store. This search warns a user about a failure to validate a certificate using python3 request.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-05-24
- **Author**: Rod Soto, Splunk
- **ID**: 839d12a6-b119-4d44-ac4f-13eed95412c8


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1588.004](https://attack.mitre.org/techniques/T1588/004/) | Digital Certificates | Resource Development |

#### Search

```
`splunk_python` "simpleRequest SSL certificate validation is enabled without hostname verification" 
| stats count by host path 
| `splunk_protocol_impersonation_weak_encryption_simplerequest_filter`
```

#### Associated Analytic Story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)


#### How To Implement
Must upgrade to Splunk version 9 and Configure TLS host name validation for Splunk Python modules in order to apply this search. Splunk SOAR customers can find a SOAR workbook that walks an analyst through the process of running these hunting searches in the references list of this detection. In order to use this workbook, a user will need to run a curl command to post the file to their SOAR instance such as &#34;curl -u username:password https://soar.instance.name/rest/rest/workbook_template -d @splunk_psa_0622.json&#34;. A user should then create an empty container or case, attach the workbook, and begin working through the tasks.

#### Required field
* host
* event_message
* path


#### Kill Chain Phase
* Exploitation


#### Known False Positives
This search tries to address validation of server and client certificates within Splunk infrastructure, it might produce results from accidental or unintended requests to port 8089.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | Failed to validate certificate on $host$ |



#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2022-32152](https://nvd.nist.gov/vuln/detail/CVE-2022-32152) | Splunk Enterprise peers in Splunk Enterprise versions before 9.0 and Splunk Cloud Platform versions before 8.2.2203 did not validate the TLS certificates during Splunk-to-Splunk communications by default. Splunk peer communications configured properly with valid certificates were not vulnerable. However, an attacker with administrator credentials could add a peer without a valid certificate and connections from misconfigured nodes without valid certificates did not fail by default. For Splunk Enterprise, update to Splunk Enterprise version 9.0 and Configure TLS host name validation for Splunk-to-Splunk communications (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation) to enable the remediation. | 6.5 |



#### Reference

* [https://www.splunk.com/en_us/product-security](https://www.splunk.com/en_us/product-security)
* [https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation](https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation)
* [https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json](https://www.github.com/splunk/security_content/blob/develop/workbooks/splunk_psa_0622.json)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1558.004/splk_protocol_impersonation_weak_encryption_simplerequest.txt](https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1558.004/splk_protocol_impersonation_weak_encryption_simplerequest.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_protocol_impersonation_weak_encryption_simplerequest.yml) \| *version*: **1**