---
title: "ConnectWise ScreenConnect Vulnerabilities"
last_modified_at: 2024-02-21
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic story provides a comprehensive overview of the ConnectWise ScreenConnect vulnerabilities.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2024-02-21
- **Author**: Michael Haag, Splunk
- **ID**: fbee3185-748c-40d8-a60c-c2e2c9eb738b

#### Narrative

The following analytic story includes content for recently disclosed CWE-288 Authentication Bypass and CWE-22 Path Traversal. The vulnerabilities, identified as critical with CVSS scores of 10 and 9.8, respectively, enable unauthorized users to bypass authentication and perform path traversal attacks on affected ScreenConnect instances. The analytic story includes detection analytics for both vulnerabilities, which are crucial for identifying and responding to active exploitation in environments running affected versions of ScreenConnect (23.9.7 and prior). It is recommended to update to version 23.9.8 or above immediately to remediate the issues, as detailed in the ConnectWise security advisory and further analyzed by Huntress researchers. The analytic story also includes guidance on how to implement the detection analytics, known false positives, and references to additional resources for further analysis and remediation.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [ConnectWise ScreenConnect Authentication Bypass](/web/d3f7a803-e802-448b-8eb2-e796b223bfff/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ConnectWise ScreenConnect Path Traversal](/endpoint/56a3ac65-e747-41f7-b014-dff7423c1dda/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ConnectWise ScreenConnect Path Traversal Windows SACL](/endpoint/4e127857-1fc9-4c95-9d69-ba24c91d52d7/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-screenconnect-authentication-bypass](https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-screenconnect-authentication-bypass)
* [https://www.huntress.com/blog/detection-guidance-for-connectwise-cwe-288-2](https://www.huntress.com/blog/detection-guidance-for-connectwise-cwe-288-2)
* [https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8](https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/connectwise_screenconnect_vulnerabilities.yml) \| *version*: **1**