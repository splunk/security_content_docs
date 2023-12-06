---
title: "Office 365 Persistence Mechanisms"
last_modified_at: 2023-10-17
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Change
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Office 365 (O365) is Microsoft's cloud-based suite of productivity tools, encompassing email, collaboration platforms, and office applications, all integrated with Azure Active Directory for identity and access management. Given the centralized storage of sensitive organizational data within O365 and its widespread adoption, it has become a focal point for cybersecurity efforts. The platform's complexity, combined with its ubiquity, makes it both a valuable asset and a prime target for potential threats. The "Office 365 Persistence Mechanisms" analytic story delves into the tactics and techniques attackers employ to maintain prolonged unauthorized access within the O365 environment. Persistence in this context refers to methods used by adversaries to keep their foothold after an initial compromise. This can involve actions like modifying mailbox rules, establishing covert forwarding rules, manipulating application permissions. Recognizing these indicators is crucial, as persistent threats can lead to long-term data exfiltration, further system compromises, and a range of other malicious activities. Monitoring for signs of persistence ensures that organizations can detect and respond to these stealthy threats, safeguarding their O365 assets and data.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2023-10-17
- **Author**: Mauricio Velazco, Splunk
- **ID**: d230a106-0475-4605-a8d8-abaf4c31ced7

#### Narrative

Monitor for activities and anomalies indicative of potential persistence techniques within Office 365 environments.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [O365 Add App Role Assignment Grant User](/cloud/b2c81cc6-6040-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Added Service Principal](/cloud/1668812a-6047-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Advanced Audit Disabled](/cloud/49862dd4-9cb2-4c48-a542-8c8a588d9361/) | [Impair Defenses](/tags/#impair-defenses), [Disable or Modify Cloud Logs](/tags/#disable-or-modify-cloud-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Application Registration Owner Added](/cloud/c068d53f-6aaa-4558-8011-3734df878266/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 ApplicationImpersonation Role Assigned](/cloud/49cdce75-f814-4d56-a7a4-c64ec3a481f2/) | [Account Manipulation](/tags/#account-manipulation), [Additional Email Delegate Permissions](/tags/#additional-email-delegate-permissions) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Bypass MFA via Trusted IP](/cloud/c783dd98-c703-4252-9e8a-f19d9f66949e/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Disable MFA](/cloud/c783dd98-c703-4252-9e8a-f19d9f5c949e/) | [Modify Authentication Process](/tags/#modify-authentication-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 High Privilege Role Granted](/cloud/e78a1037-4548-4072-bb1b-ad99ae416426/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Mailbox Inbox Folder Shared with All Users](/cloud/21421896-a692-4594-9888-5faeb8a53106/) | [Email Collection](/tags/#email-collection), [Remote Email Collection](/tags/#remote-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Mailbox Read Access Granted to Application](/cloud/27ab61c5-f08a-438a-b4d3-325e666490b3/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection), [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 New Federated Domain Added](/cloud/e155876a-6048-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 New MFA Method Registered](/cloud/4e12db1f-f7c7-486d-8152-a221cad6ac2b/) | [Account Manipulation](/tags/#account-manipulation), [Device Registration](/tags/#device-registration) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 PST export alert](/cloud/5f694cc4-a678-4a60-9410-bffca1b647dc/) | [Email Collection](/tags/#email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Service Principal New Client Credentials](/cloud/a1b229e9-d962-4222-8c62-905a8a010453/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Credentials](/tags/#additional-cloud-credentials) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious Admin Email Forwarding](/cloud/7f398cfb-918d-41f4-8db8-2e2474e02c28/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious Rights Delegation](/cloud/b25d2973-303e-47c8-bacd-52b61604c6a7/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection), [Additional Email Delegate Permissions](/tags/#additional-email-delegate-permissions), [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious User Email Forwarding](/cloud/f8dfe015-dbb3-4569-ba75-b13787e06aa4/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Tenant Wide Admin Consent Granted](/cloud/50eaabf8-5180-4e86-bfb2-011472c359fc/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)
* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://www.cisa.gov/uscert/ncas/alerts/aa21-008a](https://www.cisa.gov/uscert/ncas/alerts/aa21-008a)
* [https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html](https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html)
* [https://blog.sygnia.co/detection-and-hunting-of-golden-saml-attack?hsLang=en](https://blog.sygnia.co/detection-and-hunting-of-golden-saml-attack?hsLang=en)
* [https://www.mandiant.com/sites/default/files/2022-08/remediation-hardening-strategies-for-m365-defend-against-apt29-white-paper.pdf](https://www.mandiant.com/sites/default/files/2022-08/remediation-hardening-strategies-for-m365-defend-against-apt29-white-paper.pdf)
* [https://www.csoonline.com/article/570381/microsoft-365-advanced-audit-what-you-need-to-know.html](https://www.csoonline.com/article/570381/microsoft-365-advanced-audit-what-you-need-to-know.html)
* [https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-assign-app-owners](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-assign-app-owners)
* [https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf](https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/office_365_persistence_mechanisms.yml) \| *version*: **1**