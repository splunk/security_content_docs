---
title: "Risk Notable Import Data"
last_modified_at: 2021-10-22
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Splunk
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook gathers all of the events associated with the risk notable and imports them as artifacts. It also generates a custom markdown formatted note.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar)
- **Last Updated**: 2021-10-22
- **Author**: Kelby Shelton, Splunk
- **ID**: rn0edc96-ff2b-48b0-9f6f-23da3783fd63
- **Use-cases**:

#### Associated Detections


#### How To Implement
For detailed implementation see https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/risk_notable_import_data.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/risk_notable_import_data.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/risk_notable_import_data.json)

#### Required field
* event_id
* info_min_time
* info_max_time
* risk_object
* risk_object_type


#### Reference

* [https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack](https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack)
* [http://docs.splunk.com/Documentation/ES/6.6.2/Admin/Configurecorrelationsearches#Use_security_framework_annotations_in_correlation_searches](http://docs.splunk.com/Documentation/ES/6.6.2/Admin/Configurecorrelationsearches#Use_security_framework_annotations_in_correlation_searches)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/risk_notable_import_data.yml) \| *version*: **1**