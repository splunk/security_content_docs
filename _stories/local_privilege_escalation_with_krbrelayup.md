---
title: "Local Privilege Escalation With KrbRelayUp"
last_modified_at: 2022-04-28
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Change
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

KrbRelayUp is a tool that allows local privilege escalation from low-priviliged domain user to local system on domain-joined computers.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2022-04-28
- **Author**: Michael Haag, Mauricio Velazco, Splunk
- **ID**: 765790f0-2f8f-4048-8321-fd1928ec2546

#### Narrative

In October 2021, James Forshaw from Googles Project Zero released a research  blog post titled `Using Kerberos for Authentication Relay Attacks`. This research introduced, for the first time, ways to make Windows authenticate to a different Service Principal Name (SPN) than what would normally be derived from the hostname the client is connecting to. This effectively proved that relaying Kerberos authentication is possible\\. In April 2022, security researcher Mor Davidovich released a tool named KrbRelayUp which implements Kerberos relaying as well as other known Kerberos techniques with the goal of escalating privileges from a low-privileged domain user on a domain-joined device and obtain a SYSTEM shell.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows Computer Account Created by Computer Account](/endpoint/97a8dc5f-8a7c-4fed-9e3e-ec407fd0268a/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Computer Account Requesting Kerberos Ticket](/endpoint/fb3b2bb3-75a4-4279-848a-165b42624770/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Computer Account With SPN](/endpoint/9a3e57e7-33f4-470e-b25d-165baa6e8357/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Kerberos Local Successful Logon](/endpoint/8309c3a8-4d34-48ae-ad66-631658214653/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows KrbRelayUp Service Creation](/endpoint/e40ef542-8241-4419-9af4-6324582ea60a/) | [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
* [https://gist.github.com/tothi/bf6c59d6de5d0c9710f23dae5750c4b9](https://gist.github.com/tothi/bf6c59d6de5d0c9710f23dae5750c4b9)
* [https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
* [https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
* [https://github.com/cube0x0/KrbRelay](https://github.com/cube0x0/KrbRelay)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/local_privilege_escalation_with_krbrelayup.yml) \| *version*: **1**