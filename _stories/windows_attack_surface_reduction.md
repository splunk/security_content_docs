---
title: "Windows Attack Surface Reduction"
last_modified_at: 2023-11-27
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story contains detections for Windows Attack Surface Reduction (ASR) events. ASR is a feature of Windows Defender Exploit Guard that prevents actions and apps that are typically used by exploit-seeking malware to infect machines. ASR rules are applied to processes and applications. When a process or application attempts to perform an action that is blocked by an ASR rule, an event is generated. This story contains detections for ASR events that are generated when a process or application attempts to perform an action that is blocked by an ASR rule.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2023-11-27
- **Author**: Michael Haag, Splunk
- **ID**: 1d61c474-3cd6-4c23-8c68-f128ac4b209b

#### Narrative

This story contains detections for Windows Attack Surface Reduction (ASR) events. ASR is a feature of Windows Defender Exploit Guard that prevents actions and apps that are typically used by exploit-seeking malware to infect machines. ASR rules are applied to processes and applications. When a process or application attempts to perform an action that is blocked by an ASR rule, an event is generated. This story contains detections for ASR events that are generated when a process or application attempts to perform an action that is blocked by an ASR rule. It includes detections for both block and audit event IDs. Block event IDs are generated when an action is blocked by an ASR rule, while audit event IDs are generated when an action that would be blocked by an ASR rule is allowed to proceed for auditing purposes.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows Defender ASR Audit Events](/endpoint/0e4d46b1-22bd-4f0e-8337-ca6f60ad4bea/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Spearphishing Attachment](/tags/#spearphishing-attachment), [Spearphishing Link](/tags/#spearphishing-link) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender ASR Block Events](/endpoint/026f5f4e-e99f-4155-9e63-911ba587300b/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Spearphishing Attachment](/tags/#spearphishing-attachment), [Spearphishing Link](/tags/#spearphishing-link) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender ASR Registry Modification](/endpoint/6a1b6cbe-6612-44c3-92b9-1a1bd77412eb/) | [Modify Registry](/tags/#modify-registry) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender ASR Rule Disabled](/endpoint/429d611b-3183-49a7-b235-fc4203c4e1cb/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender ASR Rules Stacking](/endpoint/425a6657-c5e4-4cbb-909e-fc9e5d326f01/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Spearphishing Link](/tags/#spearphishing-link), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://asrgen.streamlit.app/](https://asrgen.streamlit.app/)
* [https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_attack_surface_reduction.yml) \| *version*: **1**