---
title: "Kubernetes Sensitive Object Access Activity"
last_modified_at: 2020-05-20
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story addresses detection and response of accounts acccesing Kubernetes cluster sensitive objects such as configmaps or secrets providing information on items such as user user, group. object, namespace and authorization reason.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-05-20
- **Author**: Rod Soto, Splunk
- **ID**: c7d4dbf0-a171-4eaf-8444-4f40392e4f92

#### Narrative

Kubernetes is the most used container orchestration platform, this orchestration platform contains sensitive objects within its architecture, specifically configmaps and secrets, if accessed by an attacker can lead to further compromise. These searches allow operator to detect suspicious requests against Kubernetes sensitive objects.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS EKS Kubernetes cluster sensitive object access](/deprecated/7f227943-2196-4d4d-8d6a-ac8cb308e61c/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes AWS detect service accounts forbidden failure access](/deprecated/a6959c57-fa8f-4277-bb86-7c32fba579d5/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Azure detect sensitive object access](/deprecated/1bba382b-07fd-4ffa-b390-8002739b76e8/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Azure detect service accounts forbidden failure access](/deprecated/019690d7-420f-4da0-b320-f27b09961514/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Azure detect suspicious kubectl calls](/deprecated/4b6d1ba8-0000-4cec-87e6-6cbbd71651b5/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes GCP detect sensitive object access](/deprecated/bdb6d596-86a0-4aba-8369-418ae8b9963a/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes GCP detect service accounts forbidden failure access](/deprecated/7094808d-432a-48e7-bb3c-77e96c894f3b/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes GCP detect suspicious kubectl calls](/deprecated/a5bed417-070a-41f2-a1e4-82b6aa281557/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html](https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/kubernetes_sensitive_object_access_activity.yml) \| *version*: **1**