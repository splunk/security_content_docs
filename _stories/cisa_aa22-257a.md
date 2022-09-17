---
title: "CISA AA22-257A"
last_modified_at: 2022-09-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The Iranian government-sponsored APT actors are actively targeting a broad range of victims across multiple U.S. critical infrastructure sectors, including the Transportation Sector and the Healthcare and Public Health Sector, as well as Australian organizations.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-09-15
- **Author**: Michael Haag, Splunk
- **ID**: e1aec96e-bc7d-4edf-8ff7-3da9b7b29147

#### Narrative

This advisory updates joint CSA Iranian Government-Sponsored APT Cyber Actors Exploiting Microsoft Exchange and Fortinet Vulnerabilities in Furtherance of Malicious Activities, which provides information on these Iranian government-sponsored APT actors exploiting known Fortinet and Microsoft Exchange vulnerabilities to gain initial access to a broad range of targeted entities in furtherance of malicious activities, including ransom operations. The authoring agencies now judge these actors are an APT group affiliated with the IRGC. Since the initial reporting of this activity in the FBI Liaison Alert System (FLASH) report APT Actors Exploiting Fortinet Vulnerabilities to Gain Access for Malicious Activity from May 2021, the authoring agencies have continued to observe these IRGC-affiliated actors exploiting known vulnerabilities for initial access. In addition to exploiting Fortinet and Microsoft Exchange vulnerabilities, the authoring agencies have observed these APT actors exploiting VMware Horizon Log4j vulnerabilities for initial access. The IRGC-affiliated actors have used this access for follow-on activity, including disk encryption and data extortion, to support ransom operations. The IRGC-affiliated actors are actively targeting a broad range of entities, including entities across multiple U.S. critical infrastructure sectors as well as Australian, Canadian, and United Kingdom organizations. These actors often operate under the auspices of Najee Technology Hooshmand Fater LLC, based in Karaj, Iran, and Afkar System Yazd Company, based in Yazd, Iran. The authoring agencies assess the actors are exploiting known vulnerabilities on unprotected networks rather than targeting specific targeted entities or sectors. This advisory provides observed tactics, techniques, and indicators of compromise (IOCs) that the authoring agencies assess are likely associated with this IRGC-affiliated APT. The authoring agencies urge organizations, especially critical infrastructure organizations, to apply the recommendations listed in the Mitigations section of this advisory to mitigate risk of compromise from these IRGC-affiliated cyber actors.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Create local admin accounts using net exe](/endpoint/b89919ed-fe5f-492c-b139-151bb162040e/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Creation of lsass Dump with Taskmgr](/endpoint/b2fbe95a-9c62-4c12-8a29-24b97e84c0cd/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Exchange Web Shell](/endpoint/8c14eeee-2af1-4a4b-bda8-228da0f4862a/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz Using Loaded Images](/endpoint/29e307ba-40af-4ab2-91b2-3c6b392bbba0/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect New Local Admin account](/endpoint/b25f6f62-0712-43c1-b203-083231ffd97d/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via procdump](/endpoint/3742ebfe-64c2-11eb-ae93-0242ac130002/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via procdump Rename](/deprecated/21276daa-663d-11eb-ae93-0242ac130002/) | [LSASS Memory](/tags/#lsass-memory) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Extraction of Registry Hives](/endpoint/8bbb7d58-b360-11eb-ba21-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Log4Shell JNDI Payload Injection Attempt](/web/c184f12e-5c90-11ec-bf1f-497c9a704a72/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Randomly Generated Scheduled Task Name](/endpoint/9d22a780-5165-11ec-ad4f-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks Run Task On Demand](/endpoint/bb37061e-af1f-11eb-a159-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Short Lived Scheduled Task](/endpoint/6fa31414-546e-11ec-adfa-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/5d9c6eee-988c-11eb-8253-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/203ef0ea-9bd8-11eb-8201-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hidden Schedule Task Settings](/endpoint/0b730470-5fe8-4b13-93a7-fe0ad014d0cc/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Possible Credential Dumping](/endpoint/e4723b92-7266-11ec-af45-acde48001122/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Protocol Tunneling with Plink](/endpoint/8aac5e1e-0fab-4437-af0b-c6e60af23eed/) | [Protocol Tunneling](/tags/#protocol-tunneling), [SSH](/tags/#ssh) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cisa.gov/uscert/ncas/alerts/aa21-321a](https://www.cisa.gov/uscert/ncas/alerts/aa21-321a)
* [https://www.cisa.gov/uscert/ncas/alerts/aa22-257a](https://www.cisa.gov/uscert/ncas/alerts/aa22-257a)
* [https://www.ic3.gov/Media/News/2021/210527.pdf](https://www.ic3.gov/Media/News/2021/210527.pdf)
* [https://www.us-cert.gov/sites/default/files/AA22-257A.stix.xml](https://www.us-cert.gov/sites/default/files/AA22-257A.stix.xml)
* [https://www.us-cert.cisa.gov/iran](https://www.us-cert.cisa.gov/iran)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cisa_aa22_257a.yml) \| *version*: **1**