---
title: "Suspicious Okta Activity"
last_modified_at: 2020-04-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your Okta environment for suspicious activities. Due to the Covid outbreak, many users are migrating over to leverage cloud services more and more. Okta is a popular tool to manage multiple users and the web-based applications they need to stay productive. The searches in this story will help monitor your Okta environment for suspicious activities and associated user behaviors.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
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
| [Multiple Okta Users With Invalid Credentials From The Same IP](/application/19cba45f-cad3-4032-8911-0c09e0444552/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Account Lockout Events](/application/62b70968-a0a5-4724-8ac4-67871e6f544d/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Failed SSO Attempts](/application/371a6545-2618-4032-ad84-93386b8698c5/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta User Logins From Multiple Cities](/application/7594fa07-9f34-4d01-81cc-d6af6a5db9e8/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1078](https://attack.mitre.org/wiki/Technique/T1078)
* [https://owasp.org/www-community/attacks/Credential_stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
* [https://searchsecurity.techtarget.com/answer/What-is-a-password-spraying-attack-and-how-does-it-work](https://searchsecurity.techtarget.com/answer/What-is-a-password-spraying-attack-and-how-does-it-work)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_okta_activity.yml) \| *version*: **1**