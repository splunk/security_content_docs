---
title: "Office 365 Detections"
last_modified_at: 2020-12-16
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story is focused around detecting Office 365 Attacks.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2020-12-16
- **Author**: Patrick Bareiss, Splunk
- **ID**: 1a51dd71-effc-48b2-abc4-3e9cdb61e5b9

#### Narrative

More and more companies are using Microsofts Office 365 cloud offering. Therefore, we see more and more attacks against Office 365. This story provides various detections for Office 365 attacks.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [High Number of Login Failures from a single source](/cloud/7f398cfb-918d-41f4-8db8-2e2474e02222/) | [Password Guessing](/tags/#password-guessing), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Add App Role Assignment Grant User](/cloud/b2c81cc6-6040-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Added Service Principal](/cloud/1668812a-6047-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Bypass MFA via Trusted IP](/cloud/c783dd98-c703-4252-9e8a-f19d9f66949e/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Disable MFA](/cloud/c783dd98-c703-4252-9e8a-f19d9f5c949e/) | [Modify Authentication Process](/tags/#modify-authentication-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Excessive Authentication Failures Alert](/cloud/d441364c-349c-453b-b55f-12eccab67cf9/) | [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Excessive SSO logon errors](/cloud/8158ccc4-6038-11eb-ae93-0242ac130002/) | [Modify Authentication Process](/tags/#modify-authentication-process) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 New Federated Domain Added](/cloud/e155876a-6048-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 PST export alert](/cloud/5f694cc4-a678-4a60-9410-bffca1b647dc/) | [Email Collection](/tags/#email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious Admin Email Forwarding](/cloud/7f398cfb-918d-41f4-8db8-2e2474e02c28/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious Rights Delegation](/cloud/b25d2973-303e-47c8-bacd-52b61604c6a7/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious User Email Forwarding](/cloud/f8dfe015-dbb3-4569-ba75-b13787e06aa4/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf](https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/office_365_detections.yml) \| *version*: **1**