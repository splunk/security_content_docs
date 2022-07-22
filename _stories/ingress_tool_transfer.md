---
title: "Ingress Tool Transfer"
last_modified_at: 2021-03-24
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Processes
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-03-24
- **Author**: Michael Haag, Splunk
- **ID**: b3782036-8cbd-11eb-9d8e-acde48001122

#### Narrative

Ingress tool transfer is a Technique under tactic Command and Control. Behaviors will include the use of living off the land binaries to download implants or binaries over alternate communication ports. It is imperative to baseline applications on endpoints to understand what generates network activity, to where, and what is its native behavior. These utilities, when abused, will write files to disk in world writeable paths.\ During triage, review the reputation of the remote public destination IP or domain. Capture any files written to disk and perform analysis. Review other parrallel processes for additional behaviors.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadFile](/endpoint/1a93b7ea-7af7-11eb-adb5-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Any Powershell DownloadString](/endpoint/4d015ef2-7adf-11eb-95da-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [BITSAdmin Download File](/endpoint/80630ff4-8e4c-11eb-aab5-acde48001122/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/415b4306-8bfb-11eb-85c4-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/801ad9e4-8bfb-11eb-8b31-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Curl Download and Bash Execution](/endpoint/900bc324-59f3-11ec-9fb4-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Curl Network Connection](/endpoint/3f613dc0-21f2-4063-93b1-5d3c15eef22f/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wget Download and Bash Execution](/endpoint/35682718-5a85-11ec-b8f7-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Bitsadmin Download File](/endpoint/d76e8188-8f5a-11ec-ace4-acde48001122/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows CertUtil URLCache Download](/endpoint/8cb1ad38-8f6d-11ec-87a3-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows CertUtil VerifyCtl Download](/endpoint/9ac29c40-8f6b-11ec-b19a-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Curl Download to Suspicious Path](/endpoint/c32f091e-30db-11ec-8738-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Curl Upload to Remote Destination](/endpoint/cc8d046a-543b-11ec-b864-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Curl Upload to Remote Destination](/endpoint/42f8f1a2-4228-11ec-aade-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Powershell DownloadFile](/endpoint/46440222-81d5-44b1-a376-19dcd70d1b08/) | [Automated Exfiltration](/tags/#automated-exfiltration) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ingress_tool_transfer.yml) \| *version*: **1**