---
title: "CISA AA22-277A"
last_modified_at: 2022-10-05
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

From November 2021 through January 2022, the Cybersecurity and Infrastructure Security Agency (CISA) responded to advanced persistent threat (APT) activity on a Defense Industrial Base (DIB) Sector organization's enterprise network. During incident response activities, multiple utilities were utilized.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-10-05
- **Author**: Michael Haag, Splunk
- **ID**: db408f93-e915-4215-9962-5fada348bdd7

#### Narrative

CISA uncovered that likely multiple APT groups compromised the organization's network, and some APT actors had long-term access to the environment. APT actors used an open-source toolkit called Impacket to gain their foothold within the environment and further compromise the network, and also used a custom data exfiltration tool, CovalentStealer, to steal the victim's sensitive data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CertUtil Download With URLCache and Split Arguments](/endpoint/415b4306-8bfb-11eb-85c4-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cmdline Tool Not Executed In CMD Shell](/endpoint/6c3f7dd8-153c-11ec-ac2d-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Create or delete windows shares using net exe](/endpoint/743a322c-9a68-4a0f-9c17-85d9cce2a27c/) | [Indicator Removal](/tags/#indicator-removal), [Network Share Connection Removal](/tags/#network-share-connection-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed WinRAR](/endpoint/1b7bfb2c-b8e6-11eb-99ac-acde48001122/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Taskkill](/endpoint/fe5bca48-accb-11eb-a67c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Exchange PowerShell Module Usage](/endpoint/2d10095e-05ae-11ec-8fdf-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/8ce07472-496f-11ec-ab3b-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement WMIExec Commandline Parameters](/endpoint/d6e464e4-5c6a-474e-82d2-aed616a3a492/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement smbexec CommandLine Parameters](/endpoint/bb3c1bac-6bdf-4aa0-8dc9-068b8b712a76/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Netstat](/endpoint/2cf5cc25-f39a-436d-a790-4857e5995ede/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Discovery Using Route Windows App](/endpoint/dd83407e-439f-11ec-ab8e-acde48001122/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Internet Connection Discovery](/tags/#internet-connection-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cisa.gov/uscert/ncas/alerts/aa22-277a](https://www.cisa.gov/uscert/ncas/alerts/aa22-277a)
* [https://www.cisa.gov/uscert/sites/default/files/publications/aa22-277a-impacket-and-exfiltration-tool-used-to-steal-sensitive-information-from-defense-industrial-base-organization.pdf](https://www.cisa.gov/uscert/sites/default/files/publications/aa22-277a-impacket-and-exfiltration-tool-used-to-steal-sensitive-information-from-defense-industrial-base-organization.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cisa_aa22_277a.yml) \| *version*: **1**