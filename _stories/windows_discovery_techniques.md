---
title: "Windows Discovery Techniques"
last_modified_at: 2021-03-04
toc: true
toc_label: ""
tags:
  - Splunk Behavioral Analytics
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitors for behaviors associated with adversaries discovering objects in the environment that can be leveraged in the progression of the attack.

- **Product**: Splunk Behavioral Analytics, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-03-04
- **Author**: Michael Hart, Splunk
- **ID**: f7aba570-7d59-11eb-825e-acde48001122

#### Narrative

Attackers may not have much if any insight into their target's environment before the initial compromise.  Once a foothold has been established, attackers will start enumerating objects in the environment (accounts, services, network shares, etc.) that can be used to achieve their objectives.  This Analytic Story provides searches to help identify activities consistent with adversaries gaining knowledge of compromised Windows environments.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect AzureHound Command-Line Arguments](/endpoint/26f02e96-c300-11eb-b611-acde48001122/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AzureHound File Modifications](/endpoint/1c34549e-c31b-11eb-996b-acde48001122/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect SharpHound Command-Line Arguments](/endpoint/a0bdd2f6-c2ff-11eb-b918-acde48001122/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect SharpHound File Modifications](/endpoint/42b4b438-beed-11eb-ba1d-acde48001122/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect SharpHound Usage](/endpoint/dd04b29a-beed-11eb-87bc-acde48001122/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Net Localgroup Discovery](/endpoint/54f5201e-155b-11ec-a6e2-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Traffic to Active Directory Web Services Protocol](/endpoint/68a0056c-34cb-455f-b03d-df935ea62c4f/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Information Discovery Detection](/endpoint/8e99f89e-ae58-4ebc-bf52-ae0b1a277e72/) | [System Information Discovery](/tags/#system-information-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows SOAPHound Binary Execution](/endpoint/8e53f839-e127-4d6d-a54d-a2f67044a57f/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)
* [https://cyberd.us/penetration-testing](https://cyberd.us/penetration-testing)
* [https://attack.mitre.org/software/S0521/](https://attack.mitre.org/software/S0521/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_discovery_techniques.yml) \| *version*: **1**