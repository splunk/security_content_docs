---
title: "Juniper JunOS Remote Code Execution"
last_modified_at: 2023-08-29
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Juniper Networks has resolved multiple critical vulnerabilities in the J-Web component of Junos OS on SRX and EX Series devices. These vulnerabilities, when chained together, could allow an unauthenticated, network-based attacker to remotely execute code on the devices. The vulnerabilities affect all versions of Junos OS on SRX and EX Series, but specific fixes have been released to address each vulnerability. Juniper Networks recommends applying the necessary fixes to mitigate potential remote code execution threats. As a workaround, users can disable J-Web or limit access to only trusted hosts. Proof-of-concept (PoC) exploit code has been released, demonstrating the severity of these flaws and the urgency to apply the fixes.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2023-08-29
- **Author**: Michael Haag, Splunk
- **ID**: 3fcef843-c97e-4cf3-a72f-749be480cee3

#### Narrative

Juniper Networks, a networking hardware company, has released an "out-of-cycle" security update to address multiple flaws in the J-Web component of Junos OS that could be combined to achieve remote code execution on susceptible installations. The flaws have a cumulative CVSS rating of 9.8, making them critical in severity. They affect all versions of Junos OS on SRX and EX Series. The J-Web interface allows users to configure, manage, and monitor Junos OS devices. The vulnerabilities include two PHP external variable modification vulnerabilities (CVE-2023-36844 and CVE-2023-36845) and two missing authentications for critical function vulnerabilities (CVE-2023-36846 and CVE-2023-36847). These vulnerabilities could allow an unauthenticated, network-based attacker to control certain important environment variables, cause limited impact to the file system integrity, or upload arbitrary files via J-Web without any authentication. \
The vulnerabilities have been addressed in specific Junos OS versions for EX Series and SRX Series devices. Users are recommended to apply the necessary fixes to mitigate potential remote code execution threats. As a workaround, Juniper Networks suggests disabling J-Web or limiting access to only trusted hosts. \
Additionally, a PoC exploit has been released by watchTowr, combining CVE-2023-36846 and CVE-2023-36845 to upload a PHP file containing malicious shellcode and achieve code execution by injecting the PHPRC environment variable to point to a configuration file to load the booby-trapped PHP script. WatchTowr noted that this is an interesting bug chain, utilizing two bugs that would be near-useless in isolation and combining them for a "world-ending" unauthenticated remote code execution. \
In conclusion, these vulnerabilities pose a significant threat to Juniper SRX and EX Series devices, and it is imperative for users to apply the necessary fixes or implement the recommended workaround to mitigate the potential impact.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Juniper Networks Remote Code Execution Exploit Detection](/web/6cc4cc3d-b10a-4fac-be1e-55d384fc690e/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [Ingress Tool Transfer](/tags/#ingress-tool-transfer), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution?language=en_US](https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution?language=en_US)
* [https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36844.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36844.yaml)
* [https://thehackernews.com/2023/08/new-juniper-junos-os-flaws-expose.html](https://thehackernews.com/2023/08/new-juniper-junos-os-flaws-expose.html)
* [https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844](https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844)
* [https://labs.watchtowr.com/cve-2023-36844-and-friends-rce-in-juniper-firewalls/](https://labs.watchtowr.com/cve-2023-36844-and-friends-rce-in-juniper-firewalls/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/juniper_junos_remote_code_execution.yml) \| *version*: **1**