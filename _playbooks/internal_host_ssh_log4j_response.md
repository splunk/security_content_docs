---
title: "Internal Host SSH Log4j Response"
last_modified_at: 2021-12-14
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - SSH
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Published in response to CVE-2021-44228, this playbook accepts a list of hosts and filenames to remediate on the endpoint. If filenames are provided, the endpoints will be searched and then the user can approve deletion. Then the user is prompted to quarantine the endpoint.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [SSH](https://splunkbase.splunk.com/apps?keyword=ssh&filters=product%3Asoar)
- **Last Updated**: 2021-12-14
- **Author**: Kelby Shelton, Splunk
- **ID**: 6ea2007c-8ef8-4647-a4a4-7825cfee3866
- **Use-cases**:

#### Associated Detections


#### How To Implement
The ssh asset may require ssh access to delete some files depending on their permissions.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/internal_host_ssh_log4j_respond.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/internal_host_ssh_log4j_respond.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/internal_host_ssh_log4j_respond.json)

#### Required field


#### Reference

* [https://github.com/Neo23x0/Fenrir/blob/master/fenrir.sh](https://github.com/Neo23x0/Fenrir/blob/master/fenrir.sh)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/internal_host_ssh_log4j_respond.yml) \| *version*: **1**