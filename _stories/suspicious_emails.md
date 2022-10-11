---
title: "Suspicious Emails"
last_modified_at: 2020-01-27
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Email
  - UEBA
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Email remains one of the primary means for attackers to gain an initial foothold within the modern enterprise. Detect and investigate suspicious emails in your environment with the help of the searches in this Analytic Story.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email), [UEBA](https://docs.splunk.com/Documentation/CIM/latest/User/UEBA)
- **Last Updated**: 2020-01-27
- **Author**: Bhavin Patel, Splunk
- **ID**: 2b1800dd-92f9-47ec-a981-fdf1351e5d55

#### Narrative

It is a common practice for attackers of all types to leverage targeted spearphishing campaigns and mass mailers to deliver weaponized email messages and attachments. Fortunately, there are a number of ways to monitor email data in Splunk to detect suspicious content.\
Once a phishing message has been detected, the next steps are to answer the following questions: \
1. Which users have received this or a similar message in the past?\
1. When did the targeted campaign begin?\
1. Have any users interacted with the content of the messages (by downloading an attachment or clicking on a malicious URL)?This Analytic Story provides detection searches to identify suspicious emails, as well as contextual and investigative searches to help answer some of these questions.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Email Attachments With Lots Of Spaces](/application/56e877a6-1455-4479-ada6-0550dc1e22f8/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Monitor Email For Brand Abuse](/application/b2ea1f38-3a3e-4b8a-9cf1-82760d86a6b8/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Email - UBA Anomaly](/deprecated/56e877a6-1455-4479-ad16-0550dc1e33f8/) | [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Email Attachment Extensions](/application/473bd65f-06ca-4dfe-a2b8-ba04ab4a0084/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.splunk.com/blog/2015/06/26/phishing-hits-a-new-level-of-quality/](https://www.splunk.com/blog/2015/06/26/phishing-hits-a-new-level-of-quality/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_emails.yml) \| *version*: **1**