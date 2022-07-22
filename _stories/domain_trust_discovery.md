---
title: "Domain Trust Discovery"
last_modified_at: 2021-03-25
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

Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-25
- **Author**: Michael Haag, Splunk
- **ID**: e6f30f14-8daf-11eb-a017-acde48001122

#### Narrative

Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain. Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting. Domain trusts can be enumerated using the DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP. The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [DSQuery Domain Discovery](/endpoint/cc316032-924a-11eb-91a2-acde48001122/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [NLTest Domain Trust Discovery](/endpoint/c3e05466-5f22-11eb-ae93-0242ac130002/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AdFind Exe](/endpoint/bd3b0187-189b-46c0-be45-f52da2bae67f/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/domain_trust_discovery.yml) \| *version*: **1**