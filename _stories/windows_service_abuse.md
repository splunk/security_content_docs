---
title: "Windows Service Abuse"
last_modified_at: 2017-11-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Windows services are often used by attackers for persistence and the ability to load drivers or otherwise interact with the Windows kernel. This Analytic Story helps you monitor your environment for indications that Windows services are being modified or created in a suspicious manner.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2017-11-02
- **Author**: Rico Valdez, Splunk
- **ID**: 6dbd810e-f66d-414b-8dfc-e46de55cbfe2

#### Narrative

The Windows operating system uses a services architecture to allow for running code in the background, similar to a UNIX daemon. Attackers will often leverage Windows services for persistence, hiding in plain sight, seeking the ability to run privileged code that can interact with the kernel. In many cases, attackers will create a new service to host their malicious code. Attackers have also been observed modifying unnecessary or unused services to point to their own code, as opposed to what was intended. In these cases, attackers often use tools to create or modify services in ways that are not typical for most environments, providing opportunities for detection.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [First Time Seen Running Windows Service](/endpoint/823136f2-d755-4b6d-ae04-372b486a5808/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/8470d755-0c13-45b3-bd63-387a373c10cf/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sc exe Manipulating Windows Services](/endpoint/f0c693d8-2a89-4ce7-80b4-98fea4c3ea6d/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1050](https://attack.mitre.org/wiki/Technique/T1050)
* [https://attack.mitre.org/wiki/Technique/T1031](https://attack.mitre.org/wiki/Technique/T1031)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_service_abuse.yml) \| *version*: **3**