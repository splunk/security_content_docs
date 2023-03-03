---
title: "Okta MFA Exhaustion"
last_modified_at: 2022-09-27
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Risk
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

A social engineering technique called 'MFA Fatigue', aka 'MFA push spam' or 'MFA Exhaustion', is growing more popular with threat actors as it does not require malware or phishing infrastructure and has proven to be successful in attacks.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2022-09-27
- **Author**: Michael Haag, Splunk
- **ID**: 7c6e508d-4b4d-42c8-82de-5ff4ea3b0cb3

#### Narrative

An MFA Fatigue attack is when a threat actor runs a script that attempts to log in with stolen credentials over and over, causing what feels like an endless stream of MFA push requests to be sent to the account's owner's mobile device. The goal is to keep this up, day and night, to break down the target's cybersecurity posture and inflict a sense of "fatigue" regarding these MFA prompts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Okta Account Locked Out](/application/d650c0ae-bdc5-400e-9f0f-f7aa0a010ef1/) | [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta MFA Exhaustion Hunt](/application/97e2fe57-3740-402c-988a-76b64ce04b8d/) | [Brute Force](/tags/#brute-force) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Risk Threshold Exceeded](/application/d8b967dd-657f-4d88-93b5-c588bcd7218c/) | [Valid Accounts](/tags/#valid-accounts), [Brute Force](/tags/#brute-force) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Okta Two or More Rejected Okta Pushes](/application/d93f785e-4c2c-4262-b8c7-12b77a13fd39/) | [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.bleepingcomputer.com/news/security/mfa-fatigue-hackers-new-favorite-tactic-in-high-profile-breaches/](https://www.bleepingcomputer.com/news/security/mfa-fatigue-hackers-new-favorite-tactic-in-high-profile-breaches/)
* [https://www.csoonline.com/article/3674156/multi-factor-authentication-fatigue-attacks-are-on-the-rise-how-to-defend-against-them.html](https://www.csoonline.com/article/3674156/multi-factor-authentication-fatigue-attacks-are-on-the-rise-how-to-defend-against-them.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/okta_mfa_exhaustion.yml) \| *version*: **1**