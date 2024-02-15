---
title: "Office 365 Collection Techniques"
last_modified_at: 2024-02-12
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

Monitor for activities and anomalies indicative of potential collection techniques within Office 365 environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2024-02-12
- **Author**: Mauricio Velazco, Splunk
- **ID**: d90f2b80-f675-4717-90af-12fc8c438ae8

#### Narrative

Office 365 (O365) is Microsoft's cloud-based suite of productivity tools, encompassing email, collaboration platforms, and office applications, all integrated with Azure Active Directory for identity and access management. O365's centralized storage of sensitive data and widespread adoption make it a key asset, yet also a prime target for security threats. The 'Office 365 Collection Techniques' analytic story focuses on the strategies and methodologies that attackers might use to gather critical information within the O365 ecosystem. 'Collection' in this context refers to the various techniques adversaries deploy to accumulate data that are essential for advancing their malicious objectives. This could include tactics such as intercepting communications, accessing sensitive documents, or extracting data from collaboration tools and email platforms. By identifying and monitoring these collection activities, organizations can more effectively spot and counteract attempts to illicitly gather information

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [O365 Mailbox Inbox Folder Shared with All Users](/cloud/21421896-a692-4594-9888-5faeb8a53106/) | [Email Collection](/tags/#email-collection), [Remote Email Collection](/tags/#remote-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Mailbox Read Access Granted to Application](/cloud/27ab61c5-f08a-438a-b4d3-325e666490b3/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection), [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multiple Mailboxes Accessed via API](/cloud/7cd853e9-d370-412f-965d-a2bcff2a2908/) | [Remote Email Collection](/tags/#remote-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 OAuth App Mailbox Access via EWS](/cloud/e600cf1a-0bef-4426-b42e-00176d610a4d/) | [Remote Email Collection](/tags/#remote-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 OAuth App Mailbox Access via Graph API](/cloud/9db0d5b0-4058-4cb7-baaf-77d8143539a2/) | [Remote Email Collection](/tags/#remote-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious Admin Email Forwarding](/cloud/7f398cfb-918d-41f4-8db8-2e2474e02c28/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious Rights Delegation](/cloud/b25d2973-303e-47c8-bacd-52b61604c6a7/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection), [Additional Email Delegate Permissions](/tags/#additional-email-delegate-permissions), [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious User Email Forwarding](/cloud/f8dfe015-dbb3-4569-ba75-b13787e06aa4/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference


[*source*](https://github.com/splunk/security_content/tree/develop/stories/office_365_collection_techniques.yml) \| *version*: **1**