---
title: "FIN7"
last_modified_at: 2021-09-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Risk
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the FIN7 JS Implant and JSSLoader, including looking for Image Loading of ldap and wmi modules, associated with its payload, data collection and script execution.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2021-09-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: df2b00d3-06ba-49f1-b253-b19cef19b569

#### Narrative

FIN7 is a Russian criminal advanced persistent threat group that has primarily targeted the U.S. retail, restaurant, and hospitality sectors since mid-2015. A portion of FIN7 is run out of the front company Combi Security. It has been called one of the most successful criminal hacking groups in the world. this passed few day FIN7 tools and implant are seen in the wild where its code is updated. the FIN& is known to use the spear phishing attack as a entry to targetted network or host that will drop its staging payload like the JS and JSSloader. Now this artifacts and implants seen downloading other malware like cobaltstrike and event ransomware to encrypt host.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Check Elevated CMD using whoami](/endpoint/a9079b18-1633-11ec-859c-acde48001122/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cmdline Tool Not Executed In CMD Shell](/endpoint/6c3f7dd8-153c-11ec-ac2d-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Jscript Execution Using Cscript App](/endpoint/002f1e24-146e-11ec-a470-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [MS Scripting Process Loading Ldap Module](/endpoint/0b0c40dc-14a6-11ec-b267-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [MS Scripting Process Loading WMI Module](/endpoint/2eba3d36-14a6-11ec-a682-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Application Drop Executable](/endpoint/73ce70c4-146d-11ec-9184-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning Wmic](/endpoint/ffc236d6-a6c9-11eb-95f1-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Vbscript Execution Using Wscript App](/endpoint/35159940-228f-11ec-8a49-acde48001122/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Common Abused Cmd Shell Risk Behavior](/endpoint/e99fcc4f-c6b0-4443-aa2a-e3c85126ec9a/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [System Network Connections Discovery](/tags/#system-network-connections-discovery), [System Owner/User Discovery](/tags/#system-owner/user-discovery), [System Shutdown/Reboot](/tags/#system-shutdown/reboot), [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/1f35e1da-267b-11ec-90a9-acde48001122/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [XSL Script Execution With WMIC](/endpoint/004e32e2-146d-11ec-a83f-acde48001122/) | [XSL Script Processing](/tags/#xsl-script-processing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://en.wikipedia.org/wiki/FIN7](https://en.wikipedia.org/wiki/FIN7)
* [https://threatpost.com/fin7-windows-11-release/169206/](https://threatpost.com/fin7-windows-11-release/169206/)
* [https://www.proofpoint.com/us/blog/threat-insight/jssloader-recoded-and-reloaded](https://www.proofpoint.com/us/blog/threat-insight/jssloader-recoded-and-reloaded)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/fin7.yml) \| *version*: **1**