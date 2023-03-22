---
title: "Suspicious Okta Activity"
last_modified_at: 2020-04-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Risk
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your Okta environment for suspicious activities. Due to the Covid outbreak, many users are migrating over to leverage cloud services more and more. Okta is a popular tool to manage multiple users and the web-based applications they need to stay productive. The searches in this story will help monitor your Okta environment for suspicious activities and associated user behaviors.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2020-04-02
- **Author**: Rico Valdez, Splunk
- **ID**: 9cbd34af-8f39-4476-a423-bacd126c750b

#### Narrative

Okta is the leading single sign on (SSO) provider, allowing users to authenticate once to Okta, and from there access a variety of web-based applications. These applications are assigned to users and allow administrators to centrally manage which users are allowed to access which applications. It also provides centralized logging to help understand how the applications are used and by whom. \
While SSO is a major convenience for users, it also provides attackers with an opportunity. If the attacker can gain access to Okta, they can access a variety of applications. As such monitoring the environment is important. \
With people moving quickly to adopt web-based applications and ways to manage them, many are still struggling to understand how best to monitor these environments. This analytic story provides searches to help monitor this environment, and identify events and activity that warrant further investigation such as credential stuffing or password spraying attacks, and users logging in from multiple locations when travel is disallowed.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Multiple Okta Users With Invalid Credentials From The Same IP](/application/19cba45f-cad3-4032-8911-0c09e0444552/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Account Locked Out](/application/d650c0ae-bdc5-400e-9f0f-f7aa0a010ef1/) | [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Account Lockout Events](/application/62b70968-a0a5-4724-8ac4-67871e6f544d/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Failed SSO Attempts](/application/371a6545-2618-4032-ad84-93386b8698c5/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta MFA Exhaustion Hunt](/application/97e2fe57-3740-402c-988a-76b64ce04b8d/) | [Brute Force](/tags/#brute-force) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Mismatch Between Source and Response for Verify Push Request](/application/8085b79b-9b85-4e67-ad63-351c9e9a5e9a/) | [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Multiple Failed Requests to Access Applications](/application/1c21fed1-7000-4a2e-9105-5aaafa437247/) | [Web Session Cookie](/tags/#web-session-cookie), [Cloud Service Dashboard](/tags/#cloud-service-dashboard) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta New API Token Created](/application/c3d22720-35d3-4da4-bd0a-740d37192bd4/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta New Device Enrolled on Account](/application/bb27cbce-d4de-432c-932f-2e206e9130fb/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Phishing Detection with FastPass Origin Check](/application/f4ca0057-cbf3-44f8-82ea-4e330ee901d3/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts), [Modify Authentication Process](/tags/#modify-authentication-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Risk Threshold Exceeded](/application/d8b967dd-657f-4d88-93b5-c588bcd7218c/) | [Valid Accounts](/tags/#valid-accounts), [Brute Force](/tags/#brute-force) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Suspicious Activity Reported](/application/bfc840f5-c9c6-454c-aa13-b46fd0bf1e79/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Suspicious Use of a Session Cookie](/application/71ad47d1-d6bd-4e0a-b35c-020ad9a6959e/) | [Steal Web Session Cookie](/tags/#steal-web-session-cookie) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta ThreatInsight Login Failure with High Unknown users](/application/632663b0-4562-4aad-abe9-9f621a049738/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts), [Credential Stuffing](/tags/#credential-stuffing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta ThreatInsight Suspected PasswordSpray Attack](/application/25dbad05-6682-4dd5-9ce9-8adecf0d9ae2/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts), [Password Spraying](/tags/#password-spraying) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta ThreatInsight Threat Detected](/application/140504ae-5fe2-4d65-b2bc-a211813fbca6/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Two or More Rejected Okta Pushes](/application/d93f785e-4c2c-4262-b8c7-12b77a13fd39/) | [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta User Logins From Multiple Cities](/application/7594fa07-9f34-4d01-81cc-d6af6a5db9e8/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1078](https://attack.mitre.org/wiki/Technique/T1078)
* [https://owasp.org/www-community/attacks/Credential_stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
* [https://searchsecurity.techtarget.com/answer/What-is-a-password-spraying-attack-and-how-does-it-work](https://searchsecurity.techtarget.com/answer/What-is-a-password-spraying-attack-and-how-does-it-work)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_okta_activity.yml) \| *version*: **1**