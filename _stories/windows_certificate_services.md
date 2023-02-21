---
title: "Windows Certificate Services"
last_modified_at: 2023-02-01
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

Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-02-01
- **Author**: Michael Haag, Splunk
- **ID**: b92b4ac7-0026-4408-a6b5-c1d20658e124

#### Narrative

The following analytic story focuses on remote and local endpoint certificate theft and abuse. Authentication certificates can be both stolen and forged. For example, AD CS certificates can be stolen from encrypted storage (in the Registry or files), misplaced certificate files (i.e. Unsecured Credentials), or directly from the Windows certificate store via various crypto APIs.With appropriate enrollment rights, users and/or machines within a domain can also request and/or manually renew certificates from enterprise certificate authorities (CA). This enrollment process defines various settings and permissions associated with the certificate. Abusing certificates for authentication credentials may enable other behaviors such as Lateral Movement. Certificate-related misconfigurations may also enable opportunities for Privilege Escalation, by way of allowing users to impersonate or assume privileged accounts or permissions via the identities (SANs) associated with a certificate. These abuses may also enable Persistence via stealing or forging certificates that can be used as Valid Accounts for the duration of the certificate's validity, despite user password resets. Authentication certificates can also be stolen and forged for machine accounts. (MITRE ATT&CK)

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Certutil exe certificate extraction](/endpoint/337a46be-600f-11eb-ae93-0242ac130002/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Export Certificate](/endpoint/d8ddfa9b-b724-4df9-9dbe-f34cc0936714/) | [Private Keys](/tags/#private-keys), [Unsecured Credentials](/tags/#unsecured-credentials), [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mimikatz Crypto Export File Extensions](/endpoint/3a9a6806-16a8-4cda-8d73-b49d10a05b16/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell Export Certificate](/endpoint/5e38ded4-c964-41f4-8cb6-4a1a53c6929f/) | [Private Keys](/tags/#private-keys), [Unsecured Credentials](/tags/#unsecured-credentials), [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell Export PfxCertificate](/endpoint/ed06725f-6da6-439f-9dcc-ab30e891297c/) | [Private Keys](/tags/#private-keys), [Unsecured Credentials](/tags/#unsecured-credentials), [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Steal Authentication Certificates CS Backup](/endpoint/a2f4cc7f-6503-4078-b206-f83a29f408a7/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Steal Authentication Certificates CertUtil Backup](/endpoint/bac85b56-0b65-4ce5-aad5-d94880df0967/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Steal Authentication Certificates Certificate Issued](/endpoint/9b1a5385-0c31-4c39-9753-dc26b8ce64c2/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Steal Authentication Certificates Certificate Request](/endpoint/747d7800-2eaa-422d-b994-04d8bb9e06d0/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Steal Authentication Certificates CryptoAPI](/endpoint/905d5692-6d7c-432f-bc7e-a6b4f464d40e/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Steal Authentication Certificates Export Certificate](/endpoint/e39dc429-c2a5-4f1f-9c3c-6b211af6b332/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Steal Authentication Certificates Export PfxCertificate](/endpoint/391329f3-c14b-4b8d-8b37-ac5012637360/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1649/](https://attack.mitre.org/techniques/T1649/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_certificate_services.yml) \| *version*: **1**