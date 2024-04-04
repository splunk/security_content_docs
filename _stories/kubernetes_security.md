---
title: "Kubernetes Security"
last_modified_at: 2023-12-06
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Kubernetes, as a container orchestration platform, faces unique security challenges. This story explores various tactics and techniques adversaries use to exploit Kubernetes environments, including attacking the control plane, exploiting misconfigurations, and compromising containerized applications.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2023-12-06
- **Author**: Patrick Bareiss
- **ID**: 77006b3a-306c-4e32-afd5-30b6e40c1c41

#### Narrative

Kubernetes, a widely used container orchestration system, presents a complex environment that can be targeted by adversaries. Key areas of concern include the control plane, worker nodes, and network communication. Attackers may attempt to exploit vulnerabilities in the Kubernetes API, misconfigured containers, or insecure network policies. The control plane, responsible for managing cluster operations, is a prime target. Compromising this can give attackers control over the entire cluster. Worker nodes, running the containerized applications, can be targeted to disrupt services or to gain access to sensitive data. Common attack vectors include exploiting vulnerabilities in container images, misconfigured role-based access controls (RBAC), exposed Kubernetes dashboards, and insecure network configurations. Attackers can also target the supply chain, injecting malicious code into container images or Helm charts. To mitigate these threats, it is essential to enforce robust security practices such as regular vulnerability scanning, implementing least privilege access, securing the control plane, network segmentation, and continuous monitoring for suspicious activities. Tools like Kubernetes Network Policies, Pod Security Policies, and third-party security solutions can provide additional layers of defense.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Kubernetes AWS detect suspicious kubectl calls](/cloud/042a3d32-8318-4763-9679-09db2644a8f2/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Abuse of Secret by Unusual Location](/cloud/40a064c1-4ec1-4381-9e35-61192ba8ef82/) | [Container API](/tags/#container-api) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Abuse of Secret by Unusual User Agent](/cloud/096ab390-05ca-462c-884e-343acd5b9240/) | [Container API](/tags/#container-api) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Abuse of Secret by Unusual User Group](/cloud/b6f45bbc-4ea9-4068-b3bc-0477f6997ae2/) | [Container API](/tags/#container-api) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Abuse of Secret by Unusual User Name](/cloud/df6e9cae-5257-4a34-8f3a-df49fa0f5c46/) | [Container API](/tags/#container-api) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Access Scanning](/cloud/2f4abe6d-5991-464d-8216-f90f42999764/) | [Network Service Discovery](/tags/#network-service-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Create or Update Privileged Pod](/cloud/3c6bd734-334d-4818-ae7c-5234313fc5da/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Cron Job Creation](/cloud/5984dbe8-572f-47d7-9251-3dff6c3f0c0d/) | [Container Orchestration Job](/tags/#container-orchestration-job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes DaemonSet Deployed](/cloud/bf39c3a3-b191-4d42-8738-9d9797bd0c3a/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Falco Shell Spawned](/cloud/d2feef92-d54a-4a19-8306-b47c6ceba5b2/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Node Port Creation](/cloud/d7fc865e-b8a1-4029-a960-cf4403b821b6/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Pod Created in Default Namespace](/cloud/3d6b1a81-367b-42d5-a925-6ef90b6b9f1e/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Pod With Host Network Attachment](/cloud/cce357cf-43a4-494a-814b-67cea90fe990/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Scanning by Unauthenticated IP Address](/cloud/f9cadf4e-df22-4f4e-a08f-9d3344c2165d/) | [Network Service Discovery](/tags/#network-service-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Suspicious Image Pulling](/cloud/4d3a17b3-0a6d-4ae0-9421-46623a69c122/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Unauthorized Access](/cloud/9b5f1832-e8b9-453f-93df-07a3d6a72a45/) | [User Execution](/tags/#user-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://kubernetes.io/docs/concepts/security/](https://kubernetes.io/docs/concepts/security/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/kubernetes_security.yml) \| *version*: **1**