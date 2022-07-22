---
title: "SamSam Ransomware"
last_modified_at: 2018-12-13
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the SamSam ransomware, including looking for file writes associated with SamSam, RDP brute force attacks, the presence of files with SamSam ransomware extensions, suspicious psexec use, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2018-12-13
- **Author**: Rico Valdez, Splunk
- **ID**: c4b89506-fbcf-4cb7-bfd6-527e54789604

#### Narrative

The first version of the SamSam ransomware (a.k.a. Samas or SamsamCrypt) was launched in 2015 by a group of Iranian threat actors. The malicious software has affected and continues to affect thousands of victims and has raised almost $6M in ransom.\
Although categorized under the heading of ransomware, SamSam campaigns have some importance distinguishing characteristics. Most notable is the fact that conventional ransomware is a numbers game. Perpetrators use a "spray-and-pray" approach with phishing campaigns or other mechanisms, charging a small ransom (typically under $1,000). The goal is to find a large number of victims willing to pay these mini-ransoms, adding up to a lucrative payday. They use relatively simple methods for infecting systems.\
SamSam attacks are different beasts. They have become progressively more targeted and skillful than typical ransomware attacks. First, malicious actors break into a victim's network, surveil it, then run the malware manually. The attacks are tailored to cause maximum damage and the threat actors usually demand amounts in the tens of thousands of dollars.\
In a typical attack on one large healthcare organization in 2018, the company ended up paying a ransom of four Bitcoins, then worth $56,707. Reports showed that access to the company's files was restored within two hours of paying the sum.\
According to Sophos, SamSam previously leveraged  RDP to gain access to targeted networks via brute force. SamSam is not spread automatically, like other malware. It requires skill because it forces the attacker to adapt their tactics to the individual environment. Next, the actors escalate their privileges to admin level. They scan the networks for worthy targets, using conventional tools, such as PsExec or PaExec, to deploy/execute, quickly encrypting files.\
This Analytic Story includes searches designed to help detect and investigate signs of the SamSam ransomware, such as the creation of fileswrites to system32, writes with tell-tale extensions, batch files written to system32, and evidence of brute-force attacks via RDP.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attacker Tools On Endpoint](/endpoint/a51bfe1a-94f0-48cc-b4e4-16a110145893/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Masquerading](/tags/#masquerading), [OS Credential Dumping](/tags/#os-credential-dumping), [Active Scanning](/tags/#active-scanning) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Batch File Write to System32](/endpoint/503d17cb-9eab-4cf8-a20e-01d5c6987ae3/) | [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Extensions](/endpoint/a9e5c5db-db11-43ca-86a8-c852d1b2c0ec/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Notes](/endpoint/ada0f478-84a8-4641-a3f1-d82362d6bd71/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Shadow Copies](/endpoint/b89919ed-ee5f-492c-b139-95dbb162039e/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect attackers scanning for vulnerable JBoss servers](/web/104658f4-afdc-499e-9719-17243f982681/) | [System Information Discovery](/tags/#system-information-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect malicious requests to exploit JBoss servers](/web/c8bff7a4-11ea-4416-a27d-c5bca472913d/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [File with Samsam Extension](/endpoint/02c6cfc2-ae66-4735-bfc7-6291da834cbf/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Prohibited Software On Endpoint](/deprecated/a51bfe1a-94f0-48cc-b4e4-b6ae50145893/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Desktop Network Bruteforce](/network/a98727cc-286b-4ff2-b898-41df64695923/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Desktop Network Traffic](/network/272b8407-842d-4b3d-bead-a704584003d3/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Samsam Test File Write](/endpoint/493a879d-519d-428f-8f57-a06a0fdc107e/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Spike in File Writes](/endpoint/fdb0f805-74e4-4539-8c00-618927333aae/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/](https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/)
* [https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/](https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/)
* [https://thehackernews.com/2018/07/samsam-ransomware-attacks.html](https://thehackernews.com/2018/07/samsam-ransomware-attacks.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/samsam_ransomware.yml) \| *version*: **1**