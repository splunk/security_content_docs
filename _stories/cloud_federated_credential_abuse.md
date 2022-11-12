---
title: "Cloud Federated Credential Abuse"
last_modified_at: 2021-01-26
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytical story addresses events that indicate abuse of cloud federated credentials. These credentials are usually extracted from endpoint desktop or servers specially those servers that provide federation services such as Windows Active Directory Federation Services. Identity Federation relies on objects such as Oauth2 tokens, cookies or SAML assertions in order to provide seamless access between cloud and perimeter environments. If these objects are either hijacked or forged then attackers will be able to pivot into victim's cloud environements.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-26
- **Author**: Rod Soto, Splunk
- **ID**: cecdc1e7-0af2-4a55-8967-b9ea62c0317d

#### Narrative

This story is composed of detection searches based on endpoint that addresses the use of Mimikatz, Escalation of Privileges and Abnormal processes that may indicate the extraction of Federated directory objects such as passwords, Oauth2 tokens, certificates and keys. Cloud environment (AWS, Azure) related events are also addressed in specific cloud environment detection searches.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS SAML Access by Provider User and Principal](/cloud/bbe23980-6019-11eb-ae93-0242ac130002/) | [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS SAML Update identity provider](/cloud/2f0604c6-6030-11eb-ae93-0242ac130002/) | [Valid Accounts](/tags/#valid-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Certutil exe certificate extraction](/endpoint/337a46be-600f-11eb-ae93-0242ac130002/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz Using Loaded Images](/endpoint/29e307ba-40af-4ab2-91b2-3c6b392bbba0/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz Via PowerShell And EventCode 4703](/deprecated/98917be2-bfc8-475a-8618-a9bb06575188/) | [LSASS Memory](/tags/#lsass-memory) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Add App Role Assignment Grant User](/cloud/b2c81cc6-6040-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Added Service Principal](/cloud/1668812a-6047-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Excessive SSO logon errors](/cloud/8158ccc4-6038-11eb-ae93-0242ac130002/) | [Modify Authentication Process](/tags/#modify-authentication-process) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 New Federated Domain Added](/cloud/e155876a-6048-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Privilege Escalation](/endpoint/c9f4b923-f8af-4155-b697-1354f5bcbc5e/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps)
* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cloud_federated_credential_abuse.yml) \| *version*: **1**