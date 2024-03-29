---
title: "Suspicious GCP Storage Activities"
last_modified_at: 2020-08-05
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

Use the searches in this Analytic Story to monitor your GCP Storage buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open storage buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email)
- **Last Updated**: 2020-08-05
- **Author**: Shannon Davis, Splunk
- **ID**: 4d656b2e-d6be-11ea-87d0-0242ac130003

#### Narrative

Similar to other cloud providers, GCP operates on a shared responsibility model. This means the end user, you, are responsible for setting appropriate access control lists and permissions on your GCP resources.\ This Analytics Story concentrates on detecting things like open storage buckets (both read and write) along with storage bucket access from unfamiliar users and IP addresses.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect GCP Storage access from a new IP](/cloud/ccc3246a-daa1-11ea-87d0-0242ac130022/) | [Data from Cloud Storage](/tags/#data-from-cloud-storage) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect New Open GCP Storage Buckets](/cloud/f6ea3466-d6bb-11ea-87d0-0242ac130003/) | [Data from Cloud Storage](/tags/#data-from-cloud-storage) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://cloud.google.com/blog/products/gcp/4-steps-for-hardening-your-cloud-storage-buckets-taking-charge-of-your-security](https://cloud.google.com/blog/products/gcp/4-steps-for-hardening-your-cloud-storage-buckets-taking-charge-of-your-security)
* [https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/](https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_gcp_storage_activities.yml) \| *version*: **1**