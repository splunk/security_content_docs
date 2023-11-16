---
title: "Dev Sec Ops"
last_modified_at: 2021-08-18
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Risk
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story is focused around detecting attacks on a DevSecOps lifeccycle which consists of the phases plan, code, build, test, release, deploy, operate and monitor.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2021-08-18
- **Author**: Patrick Bareiss, Splunk
- **ID**: 0ca8c38e-631e-4b81-940c-f9c5450ce41e

#### Narrative

DevSecOps is a collaborative framework, which thinks about application and infrastructure security from the start. This means that security tools are part of the continuous integration and continuous deployment pipeline. In this analytics story, we focused on detections around the tools used in this framework such as GitHub as a version control system, GDrive for the documentation, CircleCI as the CI/CD pipeline, Kubernetes as the container execution engine and multiple security tools such as Semgrep and Kube-Hunter.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS ECR Container Scanning Findings High](/cloud/30a0e9f8-f1dd-4f9d-8fc2-c622461d781c/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS ECR Container Scanning Findings Low Informational Unknown](/cloud/cbc95e44-7c22-443f-88fd-0424478f5589/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS ECR Container Scanning Findings Medium](/cloud/0b80e2c8-c746-4ddb-89eb-9efd892220cf/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS ECR Container Upload Outside Business Hours](/cloud/d4c4d4eb-3994-41ca-a25e-a82d64e125bb/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS ECR Container Upload Unknown User](/cloud/300688e4-365c-4486-a065-7c884462b31d/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Circle CI Disable Security Job](/cloud/4a2fdd41-c578-4cd4-9ef7-980e352517f2/) | [Compromise Client Software Binary](/tags/#compromise-client-software-binary) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Circle CI Disable Security Step](/cloud/72cb9de9-e98b-4ac9-80b2-5331bba6ea97/) | [Compromise Client Software Binary](/tags/#compromise-client-software-binary) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Correlation by Repository and Risk](/deprecated/8da9fdd9-6a1b-4ae0-8a34-8c25e6be9687/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Correlation by User and Risk](/deprecated/610e12dc-b6fa-4541-825e-4a0b3b6f6773/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GSuite Email Suspicious Attachment](/cloud/6d663014-fe92-11eb-ab07-acde48001122/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GitHub Actions Disable Security Workflow](/cloud/0459f1a5-c0ac-4987-82d6-65081209f854/) | [Compromise Software Supply Chain](/tags/#compromise-software-supply-chain), [Supply Chain Compromise](/tags/#supply-chain-compromise) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GitHub Dependabot Alert](/cloud/05032b04-4469-4034-9df7-05f607d75cba/) | [Compromise Software Dependencies and Development Tools](/tags/#compromise-software-dependencies-and-development-tools), [Supply Chain Compromise](/tags/#supply-chain-compromise) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GitHub Pull Request from Unknown User](/cloud/9d7b9100-8878-4404-914e-ca5e551a641e/) | [Compromise Software Dependencies and Development Tools](/tags/#compromise-software-dependencies-and-development-tools), [Supply Chain Compromise](/tags/#supply-chain-compromise) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Github Commit Changes In Master](/cloud/c9d2bfe2-019f-11ec-a8eb-acde48001122/) | [Trusted Relationship](/tags/#trusted-relationship) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Github Commit In Develop](/cloud/f3030cb6-0b02-11ec-8f22-acde48001122/) | [Trusted Relationship](/tags/#trusted-relationship) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gsuite Drive Share In External Email](/cloud/f6ee02d6-fea0-11eb-b2c2-acde48001122/) | [Exfiltration to Cloud Storage](/tags/#exfiltration-to-cloud-storage), [Exfiltration Over Web Service](/tags/#exfiltration-over-web-service) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gsuite Email Suspicious Subject With Attachment](/cloud/8ef3971e-00f2-11ec-b54f-acde48001122/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gsuite Email With Known Abuse Web Service Link](/cloud/8630aa22-042b-11ec-af39-acde48001122/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gsuite Outbound Email With Attachment To External Domain](/cloud/dc4dc3a8-ff54-11eb-8bf7-acde48001122/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gsuite Suspicious Shared File Name](/cloud/07eed200-03f5-11ec-98fb-acde48001122/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Nginx Ingress LFI](/cloud/0f83244b-425b-4528-83db-7a88c5f66e48/) | [Exploitation for Credential Access](/tags/#exploitation-for-credential-access) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Nginx Ingress RFI](/cloud/fc5531ae-62fd-4de6-9c36-b4afdae8ca95/) | [Exploitation for Credential Access](/tags/#exploitation-for-credential-access) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Scanner Image Pulling](/cloud/4890cd6b-0112-4974-a272-c5c153aee551/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Risk Rule for Dev Sec Ops by Repository](/cloud/161bc0ca-4651-4c13-9c27-27770660cf67/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dev_sec_ops.yml) \| *version*: **1**