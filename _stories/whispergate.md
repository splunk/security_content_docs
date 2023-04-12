---
title: "WhisperGate"
last_modified_at: 2022-01-19
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

This analytic story contains detections that allow security analysts to detect and investigate unusual activities that might relate to the destructive malware targeting Ukrainian organizations also known as "WhisperGate". This analytic story looks for suspicious process execution, command-line activity, downloads, DNS queries and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0150e6e5-3171-442e-83f8-1ccd8599569b

#### Narrative

WhisperGate/DEV-0586 is destructive malware operation found by MSTIC (Microsoft Threat Inteligence Center) targeting multiple organizations in Ukraine. This operation campaign consist of several malware component like the downloader that abuses discord platform, overwrite or destroy master boot record (MBR) of the targeted host, wiper and also windows defender evasion techniques.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Add or Set Windows Defender Exclusion](/endpoint/773b66fe-4dd9-11ec-8289-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempt To Stop Security Service](/endpoint/c8e349c6-b97c-486e-8949-bd7bcd1f3910/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive File Deletion In WinDefender Folder](/endpoint/b5baa09a-7a05-11ec-8da4-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/8ce07472-496f-11ec-ab3b-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ping Sleep Batch Command](/endpoint/ce058d6c-79f2-11ec-b476-acde48001122/) | [Virtualization/Sandbox Evasion](/tags/#virtualization/sandbox-evasion), [Time Based Evasion](/tags/#time-based-evasion) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Remove Windows Defender Directory](/endpoint/adf47620-79fa-11ec-b248-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Windows Defender Exclusion Commands](/endpoint/907ac95c-4dd9-11ec-ba2c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Deleting Its Process File Path](/endpoint/f7eda4bc-871c-11eb-b110-acde48001122/) | [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process DNS Query Known Abuse Web Services](/endpoint/3cf0dc36-484d-11ec-a6bc-acde48001122/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process With Discord DNS Query](/endpoint/4d4332ae-792c-11ec-89c1-acde48001122/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DotNet Binary in Non Standard Path](/endpoint/fddf3b56-7933-11ec-98a6-acde48001122/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DotNet Binary in Non Standard Path](/endpoint/21179107-099a-324a-94d3-08301e6c065f/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows High File Deletion Frequency](/endpoint/45b125c4-866f-11eb-a95a-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil in Non Standard Path](/endpoint/dcf74b22-7933-11ec-857c-acde48001122/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows LOLBin Binary in Non Standard Path](/endpoint/25689101-012a-324a-94d3-08301e6c065a/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows NirSoft AdvancedRun](/endpoint/bb4f3090-7ae4-11ec-897f-acde48001122/) | [Tool](/tags/#tool) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows NirSoft Utilities](/endpoint/5b2f4596-7d4c-11ec-88a7-acde48001122/) | [Tool](/tags/#tool) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/7b83f666-900c-11ec-a2d9-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/1f35e1da-267b-11ec-90a9-acde48001122/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)
* [https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3](https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/whispergate.yml) \| *version*: **1**