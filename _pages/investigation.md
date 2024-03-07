---
title: Investigation
layout: tag
author_profile: false
classes: wide
permalink: /playbooks/investigation/
sidebar:
  nav: "playbooks"
---

| Name    | SOAR App   | D3FEND      | Use Case    |
| --------| ---------- | ----------- | ----------- |
| [AD LDAP Account Locking](/playbooks/ad_ldap_account_locking/)| [AD LDAP](https://splunkbase.splunk.com/apps?keyword=ad+ldap&filters=product%3Asoar)| [Account Locking](https://d3fend.mitre.org/technique/d3f:AccountLocking)| [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [AD LDAP Entity Attribute Lookup](/playbooks/ad_ldap_entity_attribute_lookup/)| [AD LDAP](https://splunkbase.splunk.com/apps?keyword=ad+ldap&filters=product%3Asoar)| | [Enrichment](/playbooks/enrichment)|
| [AWS Find Inactive Users](/playbooks/aws_find_inactive_users/)| [AWS IAM](https://splunkbase.splunk.com/apps?keyword=aws+iam&filters=product%3Asoar), [Phantom](https://splunkbase.splunk.com/apps?keyword=phantom&filters=product%3Asoar)| | |
| [AWS IAM Account Locking](/playbooks/aws_iam_account_locking/)| [AWS IAM](https://splunkbase.splunk.com/apps?keyword=aws+iam&filters=product%3Asoar)| [Account Locking](https://d3fend.mitre.org/technique/d3f:AccountLocking)| [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [Active Directory Disable Account Dispatch](/playbooks/active_directory_disable_account_dispatch/)| [AD LDAP](https://splunkbase.splunk.com/apps?keyword=ad+ldap&filters=product%3Asoar), [Azure AD Graph](https://splunkbase.splunk.com/apps?keyword=azure+ad+graph&filters=product%3Asoar)| [Account Locking](https://d3fend.mitre.org/technique/d3f:AccountLocking)| [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [Attribute Lookup Dispatch](/playbooks/attribute_lookup_dispatch/)| | | [Enrichment](/playbooks/enrichment)|
| [Automated Enrichment](/playbooks/automated_enrichment/)| | | |
| [Azure AD Account Locking](/playbooks/azure_ad_account_locking/)| [Azure AD Graph](https://splunkbase.splunk.com/apps?keyword=azure+ad+graph&filters=product%3Asoar)| [Account Locking](https://d3fend.mitre.org/technique/d3f:AccountLocking)| [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [Azure AD Graph User Attribute Lookup](/playbooks/azure_ad_graph_user_attribute_lookup/)| [Azure AD Graph](https://splunkbase.splunk.com/apps?keyword=azure+ad+graph&filters=product%3Asoar)| | [Enrichment](/playbooks/enrichment)|
| [CrowdStrike OAuth API Device Attribute Lookup](/playbooks/crowdstrike_oauth_api_device_attribute_lookup/)| [CrowdStrike OAuth API](https://splunkbase.splunk.com/apps?keyword=crowdstrike+oauth+api&filters=product%3Asoar)| | [Enrichment](/playbooks/enrichment), [Endpoint](/playbooks/endpoint)|
| [CrowdStrike OAuth API Dynamic Analysis](/playbooks/crowdstrike_oauth_api_dynamic_analysis/)| [CrowdStrike OAuth API](https://splunkbase.splunk.com/apps?keyword=crowdstrike+oauth+api&filters=product%3Asoar)| [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis)| [Enrichment](/playbooks/enrichment), [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [CrowdStrike OAuth API Identifier Activity Analysis](/playbooks/crowdstrike_oauth_api_identifier_activity_analysis/)| [CrowdStrike OAuth API](https://splunkbase.splunk.com/apps?keyword=crowdstrike+oauth+api&filters=product%3Asoar)| [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Enrichment](/playbooks/enrichment), [Endpoint](/playbooks/endpoint)|
| [Dynamic Analysis Dispatch](/playbooks/dynamic_analysis_dispatch/)| | [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis)| [Enrichment](/playbooks/enrichment), [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [G Suite for GMail Message Identifier Activity Analysis](/playbooks/g_suite_for_gmail_message_identifier_activity_analysis/)| [G Suite for GMail](https://splunkbase.splunk.com/apps?keyword=g+suite+for+gmail&filters=product%3Asoar)| [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Phishing](/playbooks/phishing)|
| [Hunting](/playbooks/hunting/)| [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar), [Reversing Labs](https://splunkbase.splunk.com/apps?keyword=reversing+labs&filters=product%3Asoar), [Carbon Black Response](https://splunkbase.splunk.com/apps?keyword=carbon+black+response&filters=product%3Asoar), [Threat Grid](https://splunkbase.splunk.com/apps?keyword=threat+grid&filters=product%3Asoar), [Falcon Host API](https://splunkbase.splunk.com/apps?keyword=falcon+host+api&filters=product%3Asoar)| | |
| [Identifier Activity Analysis Dispatch](/playbooks/identifier_activity_analysis_dispatch/)| | [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Enrichment](/playbooks/enrichment)|
| [Identifier Reputation Analysis Dispatch](/playbooks/identifier_reputation_analysis_dispatch/)| | [Identifier Reputation Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis)| [Enrichment](/playbooks/enrichment)|
| [Internal Host SSH Investigate](/playbooks/internal_host_ssh_investigate/)| [SSH](https://splunkbase.splunk.com/apps?keyword=ssh&filters=product%3Asoar)| | |
| [Internal Host SSH Log4j Investigate](/playbooks/internal_host_ssh_log4j_investigate/)| [SSH](https://splunkbase.splunk.com/apps?keyword=ssh&filters=product%3Asoar)| | |
| [Internal Host WinRM Investigate](/playbooks/internal_host_winrm_investigate/)| [Windows Remote Management](https://splunkbase.splunk.com/apps?keyword=windows+remote+management&filters=product%3Asoar)| | |
| [Internal Host WinRM Log4j Investigate](/playbooks/internal_host_winrm_log4j_investigate/)| [Windows Remote Management](https://splunkbase.splunk.com/apps?keyword=windows+remote+management&filters=product%3Asoar)| | |
| [Jira Related Tickets Search](/playbooks/jira_related_tickets_search/)| [Jira](https://splunkbase.splunk.com/apps?keyword=jira&filters=product%3Asoar)| | |
| [Log4j Investigate](/playbooks/log4j_investigate/)| | | |
| [Log4j Splunk Investigation](/playbooks/log4j_splunk_investigation/)| [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar)| | |
| [MS Graph for Office 365 Message Identifier Activity Analysis](/playbooks/ms_graph_for_office_365_message_identifier_activity_analysis/)| [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)| [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Phishing](/playbooks/phishing)|
| [PhishTank URL Reputation Analysis](/playbooks/phishtank_url_reputation_analysis/)| [PhishTank](https://splunkbase.splunk.com/apps?keyword=phishtank&filters=product%3Asoar)| [Identifier Reputation Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis)| [Enrichment](/playbooks/enrichment), [Phishing](/playbooks/phishing)|
| [Related Tickets Search Dispatch](/playbooks/related_tickets_search_dispatch/)| | | [Enrichment](/playbooks/enrichment)|
| [Risk Notable Enrich](/playbooks/risk_notable_enrich/)| | | |
| [Risk Notable Import Data](/playbooks/risk_notable_import_data/)| [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar)| | |
| [Risk Notable Investigate](/playbooks/risk_notable_investigate/)| | | |
| [Risk Notable Merge Events](/playbooks/risk_notable_merge_events/)| | | |
| [Risk Notable Preprocess](/playbooks/risk_notable_preprocess/)| [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar)| | |
| [ServiceNow Related Tickets Search](/playbooks/servicenow_related_tickets_search/)| [ServiceNow](https://splunkbase.splunk.com/apps?keyword=servicenow&filters=product%3Asoar)| | [Enrichment](/playbooks/enrichment)|
| [Splunk Attack Analyzer Dynamic Analysis](/playbooks/splunk_attack_analyzer_dynamic_analysis/)| [Splunk Attack Analyzer Connector for Splunk SOAR](https://splunkbase.splunk.com/apps?keyword=splunk+attack+analyzer+connector+for+splunk+soar&filters=product%3Asoar)| [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis)| [Enrichment](/playbooks/enrichment), [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [Splunk Automated Email Investigation](/playbooks/splunk_automated_email_investigation/)| | [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis)| [Phishing](/playbooks/phishing)|
| [Splunk Identifier Activity Analysis](/playbooks/splunk_identifier_activity_analysis/)| [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar)| [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Enrichment](/playbooks/enrichment)|
| [Splunk Message Identifier Activity Analysis](/playbooks/splunk_message_identifier_activity_analysis/)| [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar)| [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Phishing](/playbooks/phishing)|
| [Splunk Notable Related Tickets Search](/playbooks/splunk_notable_related_tickets_search/)| [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar)| | [Enrichment](/playbooks/enrichment)|
| [Start Investigation](/playbooks/start_investigation/)| | | |
| [Threat Intel Investigate](/playbooks/threat_intel_investigate/)| | | |
| [TruSTAR Enrich Indicators](/playbooks/trustar_enrich_indicators/)| [TruSTAR](https://splunkbase.splunk.com/apps?keyword=trustar&filters=product%3Asoar)| | |
| [UrlScan IO Dynamic Analysis](/playbooks/urlscan_io_dynamic_analysis/)| [urlscan.io](https://splunkbase.splunk.com/apps?keyword=urlscan.io&filters=product%3Asoar)| [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis)| [Enrichment](/playbooks/enrichment), [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [VirusTotal V3 Dynamic Analysis](/playbooks/virustotal_v3_dynamic_analysis/)| [VirusTotal v3](https://splunkbase.splunk.com/apps?keyword=virustotal+v3&filters=product%3Asoar)| [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis)| [Enrichment](/playbooks/enrichment), [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [VirusTotal v3 Identifier Reputation Analysis](/playbooks/virustotal_v3_identifier_reputation_analysis/)| [VirusTotal v3](https://splunkbase.splunk.com/apps?keyword=virustotal+v3&filters=product%3Asoar)| [Identifier Reputation Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis)| [Enrichment](/playbooks/enrichment)|
| [Windows Defender ATP Identifier Activity Analysis](/playbooks/windows_defender_atp_identifier_activity_analysis/)| [Windows Defender ATP](https://splunkbase.splunk.com/apps?keyword=windows+defender+atp&filters=product%3Asoar)| [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Enrichment](/playbooks/enrichment), [Endpoint](/playbooks/endpoint)|