---
title: "Remcos"
last_modified_at: 2021-09-23
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Remcos RAT trojan, including looking for file writes associated with its payload, screencapture, registry modification, UAC bypassed, persistence and data collection..

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 2bd4aa08-b9a5-40cf-bfe5-7d43f13d496c

#### Narrative

Remcos or Remote Control and Surveillance, marketed as a legitimate software for remotely managing Windows systems is now widely used in multiple malicious campaigns both APT and commodity malware by threat actors.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Add or Set Windows Defender Exclusion](/endpoint/773b66fe-4dd9-11ec-8289-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Outlook exe writing a zip file](/endpoint/a51bfe1a-94f0-4822-b1e4-16ae10145893/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Remote User Account Control](/endpoint/bbc644bc-37df-4e1a-9c88-ec9a53e2038c/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Jscript Execution Using Cscript App](/endpoint/002f1e24-146e-11ec-a470-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Loading Of Dynwrapx Module](/endpoint/eac5e8ba-4857-11ec-9371-acde48001122/) | [Process Injection](/tags/#process-injection), [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious InProcServer32 Modification](/endpoint/127c8d08-25ff-11ec-9223-acde48001122/) | [Regsvr32](/tags/#regsvr32), [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Executing Macro Code](/endpoint/b12c89bc-9d06-11eb-a592-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawn CMD Process](/endpoint/b8b19420-e892-11eb-9244-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning Windows Script Host](/endpoint/b3628a5b-8d02-42fa-a891-eebf2351cbe1/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Possible Browser Pass View Parameter](/endpoint/8ba484e8-4b97-11ec-b19a-acde48001122/) | [Credentials from Web Browsers](/tags/#credentials-from-web-browsers), [Credentials from Password Stores](/tags/#credentials-from-password-stores) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Windows Defender Exclusion Commands](/endpoint/907ac95c-4dd9-11ec-ba2c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Deleting Its Process File Path](/endpoint/f7eda4bc-871c-11eb-b110-acde48001122/) | [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Writing DynamicWrapperX](/endpoint/b0a078e4-2601-11ec-9aec-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Component Object Model](/tags/#component-object-model) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Regsvr32 Silent and Install Param Dll Loading](/endpoint/f421c250-24e7-11ec-bc43-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Regsvr32 with Known Silent Switch Cmdline](/endpoint/c9ef7dc4-eeaf-11eb-b2b6-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remcos RAT File Creation in Remcos Folder](/endpoint/25ae862a-1ac3-11ec-94a1-acde48001122/) | [Screen Capture](/tags/#screen-capture) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remcos client registry install entry](/endpoint/f2a1615a-1d63-11ec-97d2-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Image Creation In Appdata Folder](/endpoint/f6f904c4-1ac0-11ec-806b-acde48001122/) | [Screen Capture](/tags/#screen-capture) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process DNS Query Known Abuse Web Services](/endpoint/3cf0dc36-484d-11ec-a6bc-acde48001122/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process Executed From Container File](/endpoint/d8120352-3b62-411c-8cb6-7b47584dd5e8/) | [Malicious File](/tags/#malicious-file), [Masquerade File Type](/tags/#masquerade-file-type) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious WAV file in Appdata Folder](/endpoint/5be109e6-1ac5-11ec-b421-acde48001122/) | [Screen Capture](/tags/#screen-capture) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Info Gathering Using Dxdiag Application](/endpoint/f92d74f2-4921-11ec-b685-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Vbscript Execution Using Wscript App](/endpoint/35159940-228f-11ec-8a49-acde48001122/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender Exclusion Registry Entry](/endpoint/13395a44-4dd9-11ec-9df7-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows ISO LNK File Creation](/endpoint/d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing), [Malicious Link](/tags/#malicious-link), [User Execution](/tags/#user-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Phishing Recent ISO Exec Registry](/endpoint/cb38ee66-8ae5-47de-bd66-231c7bbc0b2c/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Winhlp32 Spawning a Process](/endpoint/d17dae9e-2618-11ec-b9f5-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/1f35e1da-267b-11ec-90a9-acde48001122/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://success.trendmicro.com/solution/1123281-remcos-malware-information](https://success.trendmicro.com/solution/1123281-remcos-malware-information)
* [https://attack.mitre.org/software/S0332/](https://attack.mitre.org/software/S0332/)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos#:~:text=Remcos%20(acronym%20of%20Remote%20Control,used%20to%20remotely%20control%20computers.&text=Remcos%20can%20be%20used%20for,been%20used%20in%20hacking%20campaigns.](https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos#:~:text=Remcos%20(acronym%20of%20Remote%20Control,used%20to%20remotely%20control%20computers.&text=Remcos%20can%20be%20used%20for,been%20used%20in%20hacking%20campaigns.)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/remcos.yml) \| *version*: **1**