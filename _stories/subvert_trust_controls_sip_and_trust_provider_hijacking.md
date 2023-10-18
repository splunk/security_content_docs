---
title: "Subvert Trust Controls SIP and Trust Provider Hijacking"
last_modified_at: 2023-10-10
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

Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks. This technique involves modifying the Dll and FuncName Registry values that point to the dynamic link library (DLL) providing a SIP's function, which retrieves an encoded digital certificate from a signed file. By pointing to a maliciously-crafted DLL with an exported function that always returns a known good signature value, an adversary can apply an acceptable signature value to all files using that SIP. This can also enable persistent code execution, since these malicious components may be invoked by any application that performs code signing or signature validation.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-10-10
- **Author**: Michael Haag, Splunk
- **ID**: 7faf91b6-532a-4f18-807c-b2761e90b6dc

#### Narrative

In user mode, Windows Authenticode digital signatures are used to verify a file's origin and integrity, variables that may be used to establish trust in signed code. The signature validation process is handled via the WinVerifyTrust application programming interface (API) function, which accepts an inquiry and coordinates with the appropriate trust provider, which is responsible for validating parameters of a signature. Because of the varying executable file types and corresponding signature formats, Microsoft created software components called Subject Interface Packages (SIPs) to provide a layer of abstraction between API functions and files. SIPs are responsible for enabling API functions to create, retrieve, calculate, and verify signatures. Unique SIPs exist for most file formats and are identified by globally unique identifiers (GUIDs). Adversaries may hijack SIP and trust provider components to mislead operating system and application control tools to classify malicious (or any) code as signed.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows Registry SIP Provider Modification](/endpoint/3b4e18cb-497f-4073-85ad-1ada7c2107ab/) | [SIP and Trust Provider Hijacking](/tags/#sip-and-trust-provider-hijacking) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows SIP Provider Inventory](/endpoint/21c5af91-1a4a-4511-8603-64fb41df3fad/) | [SIP and Trust Provider Hijacking](/tags/#sip-and-trust-provider-hijacking) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows SIP WinVerifyTrust Failed Trust Validation](/endpoint/6ffc7f88-415b-4278-a80d-b957d6539e1a/) | [SIP and Trust Provider Hijacking](/tags/#sip-and-trust-provider-hijacking) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1553/003/](https://attack.mitre.org/techniques/T1553/003/)
* [https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_sip_persistence.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_sip_persistence.yml)
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/SpecterOps_Subverting_Trust_in_Windows.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/SpecterOps_Subverting_Trust_in_Windows.pdf)
* [https://github.com/gtworek/PSBits/tree/master/SIP](https://github.com/gtworek/PSBits/tree/master/SIP)
* [https://github.com/mattifestation/PoCSubjectInterfacePackage](https://github.com/mattifestation/PoCSubjectInterfacePackage)
* [https://pentestlab.blog/2017/11/06/hijacking-digital-signatures/](https://pentestlab.blog/2017/11/06/hijacking-digital-signatures/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/subvert_trust_controls_sip_and_trust_provider_hijacking.yml) \| *version*: **1**