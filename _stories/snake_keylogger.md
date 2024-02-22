---
title: "Snake Keylogger"
last_modified_at: 2024-02-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

SnakeKeylogger is a stealthy malware designed to secretly record keystrokes on infected devices. It operates covertly in the background, capturing sensitive information such as passwords and credit card details. This keylogging threat poses a significant risk to user privacy and security.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2024-02-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0374f962-c66a-4a67-9a30-24b0708ef802

#### Narrative

SnakeKeylogger, a notorious malware, first emerged in the early 2010s, gaining infamy for its clandestine ability to capture keystrokes on compromised systems. As a stealthy threat, it infiltrates computers silently, recording every keystroke entered by users, including sensitive information like passwords and financial details. Over time, it has evolved to evade detection mechanisms, posing a persistent threat to cybersecurity. Its widespread use in various cybercrime activities underscores its significance as a tool for espionage and data theft. Despite efforts to combat it, SnakeKeylogger continues to lurk in the shadows, perpetuating its malicious activities with devastating consequences.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Regasm Spawning a Process](/endpoint/72170ec5-f7d2-42f5-aefb-2b8be6aad15f/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Download Files Using Telegram](/endpoint/58194e28-ae5e-11eb-8912-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High Process Termination Frequency](/endpoint/17cd75b2-8666-11eb-9ab4-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Processes launching netsh](/endpoint/b89919ed-fe5f-492c-b139-95dbb162040e/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Driver Loaded Path](/endpoint/f880acd4-a8f1-11eb-a53b-acde48001122/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process DNS Query Known Abuse Web Services](/endpoint/3cf0dc36-484d-11ec-a6bc-acde48001122/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process Executed From Container File](/endpoint/d8120352-3b62-411c-8cb6-7b47584dd5e8/) | [Malicious File](/tags/#malicious-file), [Masquerade File Type](/tags/#masquerade-file-type) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome LocalState Access](/endpoint/3b1d09a8-a26f-473e-a510-6c6613573657/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Login Data Access](/endpoint/0d32ba37-80fc-4429-809c-0ba15801aeaf/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows File Transfer Protocol In Non-Common Process Path](/endpoint/0f43758f-1fe9-470a-a9e4-780acc4d5407/) | [Mail Protocols](/tags/#mail-protocols), [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Gather Victim Network Info Through Ip Check Web Services](/endpoint/70f7c952-0758-46d6-9148-d8969c4481d1/) | [IP Addresses](/tags/#ip-addresses), [Gather Victim Network Information](/tags/#gather-victim-network-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Non Discord App Access Discord LevelDB](/endpoint/1166360c-d495-45ac-87a6-8948aac1fa07/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Phishing PDF File Executes URL Link](/endpoint/2fa9dec8-9d8e-46d3-96c1-202c06f0e6e1/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Network Connections Discovery Netsh](/endpoint/abfb7cc5-c275-4a97-9029-62cd8d4ffeca/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Time Based Evasion via Choice Exec](/endpoint/d5f54b38-10bf-4b3a-b6fc-85949862ed50/) | [Time Based Evasion](/tags/#time-based-evasion), [Virtualization/Sandbox Evasion](/tags/#virtualization/sandbox-evasion) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unsecured Outlook Credentials Access In Registry](/endpoint/36334123-077d-47a2-b70c-6c7b3cc85049/) | [Unsecured Credentials](/tags/#unsecured-credentials) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows User Execution Malicious URL Shortcut File](/endpoint/5c7ee6ad-baf4-44fb-b2f0-0cfeddf82dbc/) | [Malicious File](/tags/#malicious-file), [User Execution](/tags/#user-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://malpedia.caad.fkie.fraunhofer.de/details/win.404keylogger](https://malpedia.caad.fkie.fraunhofer.de/details/win.404keylogger)
* [https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/snake-keylogger-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/snake-keylogger-malware/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/snake_keylogger.yml) \| *version*: **1**