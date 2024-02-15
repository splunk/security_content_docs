---
title: "NOBELIUM Group"
last_modified_at: 2020-12-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

NOBELIUM, also known as APT29, The Dukes, Cozy Bear, CozyDuke, Blue Kitsune, and Midnight Blizzard, is a sophisticated nation-state threat actor, reportedly associated with Russian intelligence. Active since at least 2008, this group primarily targets government networks in Europe and NATO member countries, along with research institutes and think tanks. Their operations typically involve advanced persistent threats (APT), leveraging techniques like spear-phishing, malware deployment, and long-term network compromise to achieve information theft and espionage. Notably, APT29 has been implicated in significant cyber espionage incidents, including the 2015 breach of the Pentagon's Joint Staff email system and attacks on the Democratic National Committee in 2016. Their advanced tactics and persistent approach underscore the serious nature of threats posed by this group to global cybersecurity.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2020-12-14
- **Author**: Patrick Bareiss, Michael Haag, Mauricio Velazco, Splunk
- **ID**: 758196b5-2e21-424f-a50c-6e421ce926c2

#### Narrative

This Analytic Story groups detections designed to trigger on a comprehensive range of Tactics, Techniques, and Procedures (TTPs) leveraged by the NOBELIUM Group, with a focus on their methods as observed in well-known public breaches.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Anomalous usage of 7zip](/endpoint/9364ee8e-a39a-11eb-8f1d-acde48001122/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Anomalous usage of Archive Tools](/endpoint/63614a58-10e2-4c6c-ae81-ea1113681439/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Admin Consent Bypassed by Service Principal](/cloud/9d4fea43-9182-4c5a-ada8-13701fd5615d/) | [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD FullAccessAsApp Permission Assigned](/cloud/ae286126-f2ad-421c-b240-4ea83bd1c43a/) | [Additional Email Delegate Permissions](/tags/#additional-email-delegate-permissions), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD High Number Of Failed Authentications From Ip](/cloud/e5ab41bf-745d-4f72-a393-2611151afd8e/) | [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing), [Password Spraying](/tags/#password-spraying) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multi-Source Failed Authentications Spike](/cloud/116e11a9-63ea-41eb-a66a-6a13bdc7d2c7/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multiple Service Principals Created by SP](/cloud/66cb378f-234d-4fe1-bb4c-e7878ff6b017/) | [Cloud Account](/tags/#cloud-account) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multiple Service Principals Created by User](/cloud/32880707-f512-414e-bd7f-204c0c85b758/) | [Cloud Account](/tags/#cloud-account) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Privileged Graph API Permission Assigned](/cloud/5521f8c5-1aa3-473c-9eb7-853701924a06/) | [Security Account Manager](/tags/#security-account-manager) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Privileged Role Assigned](/cloud/a28f0bc3-3400-4a6e-a2da-89b9e95f0d2a/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Privileged Role Assigned to Service Principal](/cloud/5dfaa3d3-e2e4-4053-8252-16d9ee528c41/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal Authentication](/cloud/5a2ec401-60bb-474e-b936-1e66e7aa4060/) | [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal Created](/cloud/f8ba49e7-ffd3-4b53-8f61-e73974583c5d/) | [Cloud Account](/tags/#cloud-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal New Client Credentials](/cloud/e3adc0d3-9e4b-4b5d-b662-12cec1adff2a/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Credentials](/tags/#additional-cloud-credentials) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal Owner Added](/cloud/7ddf2084-6cf3-4a44-be83-474f7b73c701/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Tenant Wide Admin Consent Granted](/cloud/dc02c0ee-6ac0-4c7f-87ba-8ce43a4e4418/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Outbound SMB Traffic](/network/1bed7774-304a-4e8f-9d72-d80e45ff492b/) | [File Transfer Protocols](/tags/#file-transfer-protocols), [Application Layer Protocol](/tags/#application-layer-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/dcfd6b40-42f9-469d-a433-2e53f7486664/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Rundll32 Inline HTA Execution](/endpoint/91c79f14-5b41-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [First Time Seen Running Windows Service](/endpoint/823136f2-d755-4b6d-ae04-372b486a5808/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Added Service Principal](/cloud/1668812a-6047-11eb-ae93-0242ac130002/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Application Registration Owner Added](/cloud/c068d53f-6aaa-4558-8011-3734df878266/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 ApplicationImpersonation Role Assigned](/cloud/49cdce75-f814-4d56-a7a4-c64ec3a481f2/) | [Account Manipulation](/tags/#account-manipulation), [Additional Email Delegate Permissions](/tags/#additional-email-delegate-permissions) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 FullAccessAsApp Permission Assigned](/cloud/01a510b3-a6ac-4d50-8812-7e8a3cde3d79/) | [Additional Email Delegate Permissions](/tags/#additional-email-delegate-permissions), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multi-Source Failed Authentications Spike](/cloud/ea4e2c41-dbfb-4f5f-a7b6-9ac1b7f104aa/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multiple Mailboxes Accessed via API](/cloud/7cd853e9-d370-412f-965d-a2bcff2a2908/) | [Remote Email Collection](/tags/#remote-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multiple Service Principals Created by SP](/cloud/ef4c3f20-d1ad-4ad1-a3f4-d5f391c005fe/) | [Cloud Account](/tags/#cloud-account) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multiple Service Principals Created by User](/cloud/a34e65d0-54de-4b02-9db8-5a04522067f6/) | [Cloud Account](/tags/#cloud-account) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multiple Users Failing To Authenticate From Ip](/cloud/8d486e2e-3235-4cfe-ac35-0d042e24ecb4/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 OAuth App Mailbox Access via EWS](/cloud/e600cf1a-0bef-4426-b42e-00176d610a4d/) | [Remote Email Collection](/tags/#remote-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 OAuth App Mailbox Access via Graph API](/cloud/9db0d5b0-4058-4cb7-baaf-77d8143539a2/) | [Remote Email Collection](/tags/#remote-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Privileged Graph API Permission Assigned](/cloud/868f3131-d5e1-4bf1-af5b-9b0fbaaaedbb/) | [Security Account Manager](/tags/#security-account-manager) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Service Principal New Client Credentials](/cloud/a1b229e9-d962-4222-8c62-905a8a010453/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Credentials](/tags/#additional-cloud-credentials) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Tenant Wide Admin Consent Granted](/cloud/50eaabf8-5180-4e86-bfb2-011472c359fc/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sc exe Manipulating Windows Services](/endpoint/f0c693d8-2a89-4ce7-80b4-98fea4c3ea6d/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks scheduling job on remote system](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066237cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sunburst Correlation DLL and Network Event](/endpoint/701a8740-e8db-40df-9190-5516d3819787/) | [Exploitation for Client Execution](/tags/#exploitation-for-client-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Supernova Webshell](/web/2ec08a09-9ff1-4dac-b59f-1efd57972ec1/) | [Web Shell](/tags/#web-shell), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [TOR Traffic](/network/ea688274-9c06-4473-b951-e4cb7a5d7a45/) | [Proxy](/tags/#proxy), [Multi-hop Proxy](/tags/#multi-hop-proxy) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AdFind Exe](/endpoint/bd3b0187-189b-46c0-be45-f52da2bae67f/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rundll32 Inline HTA Execution](/endpoint/0caa1dd6-94f5-11ec-9786-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/groups/G0016/](https://attack.mitre.org/groups/G0016/)
* [https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/](https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/)
* [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)
* [https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)
* [https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/nobelium_group.yml) \| *version*: **3**