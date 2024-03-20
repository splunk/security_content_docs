---
title: "Abnormal Kubernetes Behavior using Splunk Infrastructure Monitoring"
last_modified_at: 2024-01-08
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Kubernetes, a complex container orchestration system, is susceptible to a variety of security threats. This story delves into the different strategies and methods adversaries employ to exploit Kubernetes environments. These include attacks on the control plane, exploitation of misconfigurations, and breaches of containerized applications. Observability data, such as metrics, play a crucial role in identifying abnormal and potentially malicious behavior within these environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2024-01-08
- **Author**: Matthew Moore, Patrick Bareiss, Splunk
- **ID**: 7589023b-3d98-42b3-ab1c-bb498e68fc2d

#### Narrative

Kubernetes, a complex container orchestration system, is a prime target for adversaries due to its widespread use and inherent complexity. This story focuses on the abnormal behavior within Kubernetes environments that can be indicative of security threats. Key areas of concern include the control plane, worker nodes, and network communication, all of which can be exploited by attackers. Observability data, such as metrics, play a crucial role in identifying these abnormal behaviors. These behaviors could be a result of attacks on the control plane, exploitation of misconfigurations, or breaches of containerized applications. For instance, attackers may attempt to exploit vulnerabilities in the Kubernetes API, misconfigured containers, or insecure network policies. The control plane, which manages cluster operations, is a prime target and its compromise can give attackers control over the entire cluster. Worker nodes, which run the containerized applications, can also be targeted to disrupt services or to gain access to sensitive data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Kubernetes Anomalous Inbound Network Activity from Process](/cloud/10442d8b-0701-4c25-911d-d67b906e713c/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Anomalous Inbound Outbound Network IO](/cloud/4f3b0c97-657e-4547-a89a-9a50c656e3cd/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Anomalous Inbound to Outbound Network IO Ratio](/cloud/9d8f6e3f-39df-46d8-a9d4-96173edc501f/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Anomalous Outbound Network Activity from Process](/cloud/dd6afee6-e0a3-4028-a089-f47dd2842c22/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Anomalous Traffic on Network Edge](/cloud/886c7e51-2ea1-425d-8705-faaca5a64cc6/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Previously Unseen Container Image Name](/cloud/fea515a4-b1d8-4cd6-80d6-e0d71397b891/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Previously Unseen Process](/cloud/c8119b2f-d7f7-40be-940a-1c582870e8e2/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Process Running From New Path](/cloud/454076fb-0e9e-4adf-b93a-da132621c5e6/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Process with Anomalous Resource Utilisation](/cloud/25ca9594-7a0d-4a95-a5e5-3228d7398ec8/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Process with Resource Ratio Anomalies](/cloud/0d42b295-0f1f-4183-b75e-377975f47c65/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Shell Running on Worker Node](/cloud/efebf0c4-dcf4-496f-85a2-5ab7ad8fa876/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Shell Running on Worker Node with CPU Activity](/cloud/cc1448e3-cc7a-4518-bc9f-2fa48f61a22b/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes newly seen TCP edge](/cloud/13f081d6-7052-428a-bbb0-892c79ca7c65/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes newly seen UDP edge](/cloud/49b7daca-4e3c-4899-ba15-9a175e056fa9/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://kubernetes.io/docs/concepts/security/](https://kubernetes.io/docs/concepts/security/)
* [https://splunkbase.splunk.com/app/5247](https://splunkbase.splunk.com/app/5247)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/abnormal_kubernetes_behavior_using_splunk_infrastructure_monitoring.yml) \| *version*: **1**