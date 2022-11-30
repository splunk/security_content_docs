---
title: "MetaSploit"
last_modified_at: 2022-11-21
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic story highlights content related directly to MetaSploit, which may be default configurations attributed to MetaSploit or behaviors of known knowns that are related.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-11-21
- **Author**: Michael Haag, Splunk
- **ID**: c149b694-bd08-4535-88d3-1f288a66313f

#### Narrative

The Metasploit framework is a very powerful tool which can be used by cybercriminals as well as ethical hackers to probe systematic vulnerabilities on networks and servers. Because it is an open-source framework, it can be easily customized and used with most operating systems.\
The Metasploit Project was undertaken in 2003 by H.D. Moore for use as a Perl-based portable network tool, with assistance from core developer Matt Miller. It was fully converted to Ruby by 2007, and the license was acquired by Rapid7 in 2009, where it remains as part of the Boston-based company repertoire of IDS signature development and targeted remote exploit, fuzzing, anti-forensic, and evasion tools.\
Portions of these other tools reside within the Metasploit framework, which is built into the Kali Linux OS. Rapid7 has also developed two proprietary OpenCore tools, Metasploit Pro, Metasploit Express.\
This framework has become the go-to exploit development and mitigation tool. Prior to Metasploit, pen testers had to perform all probes manually by using a variety of tools that may or may not have supported the platform they were testing, writing their own code by hand, and introducing it onto networks manually. Remote testing was virtually unheard of, and that limited a security specialist reach to the local area and companies spending a fortune on in-house IT or security consultants. (ref. Varonis)

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Powershell Load Module in Meterpreter](/endpoint/d5905da5-d050-48db-9259-018d8f034fcf/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Apache Benchmark Binary](/endpoint/894f48ea-8d85-4dcd-9132-c66cdb407c9b/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)
* [https://www.varonis.com/blog/what-is-metasploit](https://www.varonis.com/blog/what-is-metasploit)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/metasploit.yml) \| *version*: **1**