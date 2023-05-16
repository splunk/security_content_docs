---
title: "Suspicious AWS S3 Activities"
last_modified_at: 2023-04-24
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Use the searches in this Analytic Story using Cloudtrail logs to to monitor your AWS S3 buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open S3 buckets and buckets being accessed from a new IP, permission and policy updates to the bucket, potential misuse of other services leading to data being leaked.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2023-04-24
- **Author**: Bhavin Patel, Splunk
- **ID**: 66732346-8fb0-407b-9633-da16756567d6

#### Narrative

One of the most common ways that attackers attempt to steal data from S3 is by gaining unauthorized access to S3 buckets and copying or exfiltrating data to external locations.\
However, suspicious S3 activities can refer to any unusual behavior detected within an Amazon Web Services (AWS) Simple Storage Service (S3) bucket, including unauthorized access, unusual data transfer patterns, and access attempts from unknown IP addresses. \
It is important for organizations to regularly monitor S3 activities for suspicious behavior and implement security best practices, such as using access controls, encryption, and strong authentication mechanisms, to protect sensitive data stored within S3 buckets. By staying vigilant and taking proactive measures, organizations can help prevent potential security breaches and minimize the impact of attacks if they do occur.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Disable Bucket Versioning](/cloud/657902a9-987d-4879-a1b2-e7a65512824b/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Exfiltration via Bucket Replication](/cloud/eeb432d6-2212-43b6-9e89-fcd753f7da4c/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Exfiltration via DataSync Task](/cloud/05c4b09f-ea28-4c7c-a7aa-a246f665c8a2/) | [Automated Collection](/tags/#automated-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect New Open S3 Buckets over AWS CLI](/cloud/39c61d09-8b30-4154-922b-2d0a694ecc22/) | [Data from Cloud Storage](/tags/#data-from-cloud-storage) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect New Open S3 buckets](/cloud/2a9b80d3-6340-4345-b5ad-290bf3d0dac4/) | [Data from Cloud Storage](/tags/#data-from-cloud-storage) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect S3 access from a new IP](/cloud/e6f1bb1b-f441-492b-9126-902acda217da/) | [Data from Cloud Storage](/tags/#data-from-cloud-storage) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Spike in S3 Bucket deletion](/cloud/e733a326-59d2-446d-b8db-14a17151aa68/) | [Data from Cloud Storage](/tags/#data-from-cloud-storage) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://github.com/nagwww/s3-leaks](https://github.com/nagwww/s3-leaks)
* [https://www.tripwire.com/state-of-security/security-data-protection/cloud/public-aws-s3-buckets-writable/](https://www.tripwire.com/state-of-security/security-data-protection/cloud/public-aws-s3-buckets-writable/)
* [None](None)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_aws_s3_activities.yml) \| *version*: **3**