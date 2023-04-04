---
title: "3CX Supply Chain Attack"
last_modified_at: 2023-03-30
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

On March 29, 2023, CrowdStrike Falcon OverWatch observed unexpected malicious activity emanating from a legitimate, signed binary, 3CXDesktopApp,  a softphone application from 3CX. The malicious activity includes beaconing to actor controlled infrastructure, deployment of second stage payloads, and, in a small number of cases, hands on keyboard activity. (CrowdStrike)

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2023-03-30
- **Author**: Michael Haag, Splunk
- **ID**: c4d7618c-73a7-4f7c-8071-060c36850785

#### Narrative

On March 22, 2023, cybersecurity firm SentinelOne observed a surge in behavioral detections of trojanized 3CXDesktopApp installers, a popular PABX voice and video conferencing software. The multi-stage attack chain, which automatically quarantines trojanized installers, involves downloading ICO files with base64 data from GitHub and eventually leads to a 3rd stage infostealer DLL that is still under analysis. While the Mac installer remains unconfirmed as trojanized, ongoing investigations are also examining other potentially compromised applications, such as Chrome extensions. The threat actor behind the supply chain compromise, which started in February 2022, has used a code signing certificate to sign the trojanized binaries, but connections to existing threat clusters remain unclear. SentinelOne updated their IOCs on March 30th, 2023, with contributions from the research community and continues to monitor the situation for further developments. 3CX identified the vulnerability in the recent versions 18.12.407 and 18.12.416 for the desktop app. A new certificate for the app will also be produced.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [3CX Supply Chain Attack Network Indicators](/network/791b727c-deec-4fbe-a732-756131b3c5a1/) | [Compromise Software Supply Chain](/tags/#compromise-software-supply-chain) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hunting 3CXDesktopApp Software](/endpoint/553d0429-1a1c-44bf-b3f5-a8513deb9ee5/) | [Compromise Software Supply Chain](/tags/#compromise-software-supply-chain) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Vulnerable 3CX Software](/endpoint/f2cc1584-46ee-485b-b905-977c067f36de/) | [Compromise Software Supply Chain](/tags/#compromise-software-supply-chain) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/](https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/)
* [https://www.cisa.gov/news-events/alerts/2023/03/30/supply-chain-attack-against-3cxdesktopapp](https://www.cisa.gov/news-events/alerts/2023/03/30/supply-chain-attack-against-3cxdesktopapp)
* [https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/](https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/)
* [https://www.3cx.com/community/threads/crowdstrike-endpoint-security-detection-re-3cx-desktop-app.119934/page-2#post-558898](https://www.3cx.com/community/threads/crowdstrike-endpoint-security-detection-re-3cx-desktop-app.119934/page-2#post-558898)
* [https://www.3cx.com/community/threads/3cx-desktopapp-security-alert.119951/](https://www.3cx.com/community/threads/3cx-desktopapp-security-alert.119951/)
* [https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack](https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack)
* [https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/](https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/3cx_supply_chain_attack.yml) \| *version*: **1**