---
title: "Kubernetes Scanning Activity"
last_modified_at: 2020-04-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Email
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story addresses detection against Kubernetes cluster fingerprint scan and attack by providing information on items such as source ip, user agent, cluster names.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email)
- **Last Updated**: 2020-04-15
- **Author**: Rod Soto, Splunk
- **ID**: a9ef59cf-e981-4e66-9eef-bb049f695c09

#### Narrative

Kubernetes is the most used container orchestration platform, this orchestration platform contains sensitve information and management priviledges of production workloads, microservices and applications. These searches allow operator to detect suspicious unauthenticated requests from the internet to kubernetes cluster.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Amazon EKS Kubernetes Pod scan detection](/cloud/dbfca1dd-b8e5-4ba4-be0e-e565e5d62002/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Amazon EKS Kubernetes cluster scan detection](/cloud/294c4686-63dd-4fe6-93a2-ca807626704a/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GCP Kubernetes cluster pod scan detection](/cloud/19b53215-4a16-405b-8087-9e6acf619842/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GCP Kubernetes cluster scan detection](/deprecated/db5957ec-0144-4c56-b512-9dccbe7a2d26/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Azure pod scan fingerprint](/deprecated/86aad3e0-732f-4f66-bbbc-70df448e461d/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kubernetes Azure scan fingerprint](/deprecated/c5e5bd5c-1013-4841-8b23-e7b3253c840a/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://github.com/splunk/cloud-datamodel-security-research](https://github.com/splunk/cloud-datamodel-security-research)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/kubernetes_scanning_activity.yml) \| *version*: **1**