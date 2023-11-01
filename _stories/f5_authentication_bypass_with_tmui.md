---
title: "F5 Authentication Bypass with TMUI"
last_modified_at: 2023-10-30
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Research into leading software revealed vulnerabilities in both Apache Tomcat and the F5 BIG-IP suite. Apache's AJP protocol vulnerability, designated CVE-2022-26377, relates to AJP request smuggling. Successful exploitation enables unauthorized system activities. F5 BIG-IP Virtual Edition exhibited a distinct vulnerability, an authentication bypass in the Traffic Management User Interface (TMUI), resulting in system compromise. Assigned CVE-2023-46747, this vulnerability also arose from request smuggling, bearing similarity to CVE-2022-26377. Given the wide adoption of both Apache Tomcat and F5 products, these vulnerabilities present grave risks to organizations. Remediation and vulnerability detection mechanisms are essential to address these threats effectively.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2023-10-30
- **Author**: Michael Haag, Splunk
- **ID**: e4acbea6-75bb-4873-8c22-bc2da9525e89

#### Narrative

Both Apache Tomcat's AJP protocol and F5's BIG-IP Virtual Edition have been exposed to critical vulnerabilities. Apache's CVE-2022-26377 pertains to request smuggling by manipulating the "Transfer-Encoding" header. If successfully exploited, this allows attackers to bypass security controls and undertake unauthorized actions. \
Similarly, F5 BIG-IP unveiled an authentication bypass vulnerability, CVE-2023-46747. Originating from the TMUI, this vulnerability leads to full system compromise. While distinct, it shares characteristics with Apache's vulnerability, primarily rooted in request smuggling. This vulnerability drew from past F5 CVEs, particularly CVE-2020-5902 and CVE-2022-1388, both previously exploited in real-world scenarios. These highlighted vulnerabilities in Apache HTTP and Apache Tomcat services, as well as authentication flaws in the F5 BIG-IP API.\
Nuclei detection templates offer a proactive solution for identifying and mitigating these vulnerabilities. Integrated into vulnerability management frameworks, these templates notify organizations of potential risks, forming a base for further detection strategies. For detection engineers, understanding these vulnerabilities is crucial. Recognizing the mechanisms and effects of request smuggling, especially in Apache's and F5's context, provides a roadmap to effective detection and response. Prompt detection is a linchpin, potentially stymieing further, more destructive attacks.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [F5 TMUI Authentication Bypass](/web/88bf127c-613e-4579-99e4-c4d4b02f3840/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.praetorian.com/blog/refresh-compromising-f5-big-ip-with-request-smuggling-cve-2023-46747/](https://www.praetorian.com/blog/refresh-compromising-f5-big-ip-with-request-smuggling-cve-2023-46747/)
* [https://github.com/projectdiscovery/nuclei-templates/blob/3b0bb71bd627c6c3139e1d06c866f8402aa228ae/http/cves/2023/CVE-2023-46747.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/3b0bb71bd627c6c3139e1d06c866f8402aa228ae/http/cves/2023/CVE-2023-46747.yaml)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/f5_authentication_bypass_with_tmui.yml) \| *version*: **1**