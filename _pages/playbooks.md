---
title: "Playbooks"
layout: collection
author_profile: false
permalink: /playbooks/
classes: wide
sidebar:
  nav: "playbooks"
---

| Name    | SOAR App   | Type        |
| --------| ---------- | ----------- |
| [AD LDAP Account Locking](/playbooks/ad_ldap_account_locking/)|[AD LDAP API](https://splunkbase.splunk.com/apps/#/search/AD LDAP API/product/soar)| Investigation |
| [AD LDAP Entity Attribute Lookup](/playbooks/ad_ldap_entity_attribute_lookup/)|[AD LDAP](https://splunkbase.splunk.com/apps/#/search/AD LDAP/product/soar)| Investigation |
| [AWS Disable User Accounts](/playbooks/aws_disable_user_accounts/)|[AWS IAM](https://splunkbase.splunk.com/apps/#/search/AWS IAM/product/soar)| Response |
| [AWS Find Inactive Users](/playbooks/aws_find_inactive_users/)|[AWS IAM](https://splunkbase.splunk.com/apps/#/search/AWS IAM/product/soar), [Phantom](https://splunkbase.splunk.com/apps/#/search/Phantom/product/soar)| Investigation |
| [AWS IAM Account Locking](/playbooks/aws_iam_account_locking/)|[AWS IAM API](https://splunkbase.splunk.com/apps/#/search/AWS IAM API/product/soar)| Investigation |
| [Active Directory Disable Account Dispatch](/playbooks/active_directory_disable_account_dispatch/)|[microsoft_ad_ldap](https://splunkbase.splunk.com/apps/#/search/microsoft_ad_ldap/product/soar), [azure_ad_graph](https://splunkbase.splunk.com/apps/#/search/azure_ad_graph/product/soar), [aws_iam](https://splunkbase.splunk.com/apps/#/search/aws_iam/product/soar)| Investigation |
| [Active Directory Reset password](/playbooks/active_directory_reset_password/)|[LDAP](https://splunkbase.splunk.com/apps/#/search/LDAP/product/soar)| Response |
| [Attribute Lookup Dispatch](/playbooks/attribute_lookup_dispatch/)| None | Investigation |
| [Automated Enrichment](/playbooks/automated_enrichment/)| None | Investigation |
| [Azure AD Graph User Attribute Lookup](/playbooks/azure_ad_graph_user_attribute_lookup/)|[Azure AD Graph](https://splunkbase.splunk.com/apps/#/search/Azure AD Graph/product/soar)| Investigation |
| [Azure AD Locking Account](/playbooks/azure_ad_locking_account/)|[Azure AD Graph API](https://splunkbase.splunk.com/apps/#/search/Azure AD Graph API/product/soar)| Investigation |
| [Block Indicators](/playbooks/block_indicators/)|[Palo Alto Networks Firewall](https://splunkbase.splunk.com/apps/#/search/Palo Alto Networks Firewall/product/soar), [CarbonBlack Response](https://splunkbase.splunk.com/apps/#/search/CarbonBlack Response/product/soar), [OpenDNS Umbrella](https://splunkbase.splunk.com/apps/#/search/OpenDNS Umbrella/product/soar)| Response |
| [CrowdStrike OAuth API Device Attribute Lookup](/playbooks/crowdstrike_oauth_api_device_attribute_lookup/)|[CrowdStrike OAuth API](https://splunkbase.splunk.com/apps/#/search/CrowdStrike OAuth API/product/soar)| Investigation |
| [CrowdStrike OAuth API Dynamic Analysis](/playbooks/crowdstrike_oauth_api_dynamic_analysis/)|[CrowdStrike OAuth API](https://splunkbase.splunk.com/apps/#/search/CrowdStrike OAuth API/product/soar)| Investigation |
| [CrowdStrike OAuth API Identifier Activity Analysis](/playbooks/crowdstrike_oauth_api_identifier_activity_analysis/)|[CrowdStrike OAuth API](https://splunkbase.splunk.com/apps/#/search/CrowdStrike OAuth API/product/soar)| Investigation |
| [Crowdstrike Malware Triage](/playbooks/crowdstrike_malware_triage/)|[Crowdstrike OAuth](https://splunkbase.splunk.com/apps/#/search/Crowdstrike OAuth/product/soar)| Response |
| [Delete Detected Files](/playbooks/delete_detected_files/)|[Windows Remote Management](https://splunkbase.splunk.com/apps/#/search/Windows Remote Management/product/soar)| Response |
| [Dynamic Analysis Dispatch](/playbooks/dynamic_analysis_dispatch/)|[CrowdStrike OAuth API](https://splunkbase.splunk.com/apps/#/search/CrowdStrike OAuth API/product/soar), [urlscan.io](https://splunkbase.splunk.com/apps/#/search/urlscan.io/product/soar), [VirusTotal_v3](https://splunkbase.splunk.com/apps/#/search/VirusTotal_v3/product/soar), [SAA](https://splunkbase.splunk.com/apps/#/search/SAA/product/soar)| Investigation |
| [Email Notification for Malware](/playbooks/email_notification_for_malware/)|[VirusTotal](https://splunkbase.splunk.com/apps/#/search/VirusTotal/product/soar), [WildFire](https://splunkbase.splunk.com/apps/#/search/WildFire/product/soar), [CarbonBlack Response](https://splunkbase.splunk.com/apps/#/search/CarbonBlack Response/product/soar), [SMTP](https://splunkbase.splunk.com/apps/#/search/SMTP/product/soar)| Response |
| [Hunting](/playbooks/hunting/)|[Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar), [Reversing Labs](https://splunkbase.splunk.com/apps/#/search/Reversing Labs/product/soar), [CarbonBlack Response](https://splunkbase.splunk.com/apps/#/search/CarbonBlack Response/product/soar), [Threat Grid](https://splunkbase.splunk.com/apps/#/search/Threat Grid/product/soar), [Falcon Host API](https://splunkbase.splunk.com/apps/#/search/Falcon Host API/product/soar)| Investigation |
| [Identifier Activity Analysis Dispatch](/playbooks/identifier_activity_analysis_dispatch/)| None | Investigation |
| [Identifier Reputation Analysis Dispatch](/playbooks/identifier_reputation_analysis_dispatch/)| None | Investigation |
| [Internal Host SSH Investigate](/playbooks/internal_host_ssh_investigate/)|[SSH](https://splunkbase.splunk.com/apps/#/search/SSH/product/soar)| Investigation |
| [Internal Host SSH Log4j Investigate](/playbooks/internal_host_ssh_log4j_investigate/)|[SSH](https://splunkbase.splunk.com/apps/#/search/SSH/product/soar)| Investigation |
| [Internal Host SSH Log4j Response](/playbooks/internal_host_ssh_log4j_response/)|[SSH](https://splunkbase.splunk.com/apps/#/search/SSH/product/soar)| Response |
| [Internal Host WinRM Investigate](/playbooks/internal_host_winrm_investigate/)|[Windows Remote Management](https://splunkbase.splunk.com/apps/#/search/Windows Remote Management/product/soar)| Investigation |
| [Internal Host WinRM Log4j Investigate](/playbooks/internal_host_winrm_log4j_investigate/)|[Windows Remote Management](https://splunkbase.splunk.com/apps/#/search/Windows Remote Management/product/soar)| Investigation |
| [Internal Host WinRM Response](/playbooks/internal_host_winrm_response/)|[Windows Remote Management](https://splunkbase.splunk.com/apps/#/search/Windows Remote Management/product/soar)| Response |
| [Log4j Investigate](/playbooks/log4j_investigate/)| None | Investigation |
| [Log4j Respond](/playbooks/log4j_respond/)| None | Response |
| [Log4j Splunk Investigation](/playbooks/log4j_splunk_investigation/)|[Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)| Investigation |
| [Malware Hunt and Contain](/playbooks/malware_hunt_and_contain/)|[LDAP](https://splunkbase.splunk.com/apps/#/search/LDAP/product/soar), [ServiceNow](https://splunkbase.splunk.com/apps/#/search/ServiceNow/product/soar), [CarbonBlack Response](https://splunkbase.splunk.com/apps/#/search/CarbonBlack Response/product/soar), [VirusTotal](https://splunkbase.splunk.com/apps/#/search/VirusTotal/product/soar)| Response |
| [PhishTank URL Reputation Analysis](/playbooks/phishtank_url_reputation_analysis/)|[PhishTank](https://splunkbase.splunk.com/apps/#/search/PhishTank/product/soar)| Investigation |
| [Ransomware Investigate and Contain](/playbooks/ransomware_investigate_and_contain/)|[Carbon Black Response](https://splunkbase.splunk.com/apps/#/search/Carbon Black Response/product/soar), [LDAP](https://splunkbase.splunk.com/apps/#/search/LDAP/product/soar), [Palo Alto Networks Firewall](https://splunkbase.splunk.com/apps/#/search/Palo Alto Networks Firewall/product/soar), [WildFire](https://splunkbase.splunk.com/apps/#/search/WildFire/product/soar), [Cylance](https://splunkbase.splunk.com/apps/#/search/Cylance/product/soar)| Response |
| [Related Tickets Search Dispatch](/playbooks/related_tickets_search_dispatch/)| None | Investigation |
| [Risk Notable Block Indicators](/playbooks/risk_notable_block_indicators/)|[None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)| Response |
| [Risk Notable Enrich](/playbooks/risk_notable_enrich/)|[None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)| Investigation |
| [Risk Notable Import Data](/playbooks/risk_notable_import_data/)|[Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)| Investigation |
| [Risk Notable Investigate](/playbooks/risk_notable_investigate/)|[None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)| Investigation |
| [Risk Notable Merge Events](/playbooks/risk_notable_merge_events/)|[None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)| Investigation |
| [Risk Notable Mitigate](/playbooks/risk_notable_mitigate/)| None | Response |
| [Risk Notable Preprocess](/playbooks/risk_notable_preprocess/)|[Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)| Investigation |
| [Risk Notable Protect Assets and Users](/playbooks/risk_notable_protect_assets_and_users/)|[None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)| Response |
| [Risk Notable Review Indicators](/playbooks/risk_notable_review_indicators/)|[None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)| Response |
| [Risk Notable Verdict](/playbooks/risk_notable_verdict/)|[None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)| Response |
| [ServiceNow Related Tickets Search](/playbooks/servicenow_related_tickets_search/)|[Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)| Investigation |
| [Splunk Identifier Activity Analysis](/playbooks/splunk_identifier_activity_analysis/)|[Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)| Investigation |
| [Splunk Notable Related Tickets Search](/playbooks/splunk_notable_related_tickets_search/)|[Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)| Investigation |
| [Splunk_Attack_Analyzer_Dynamic_Analysis](/playbooks/splunk_attack_analyzer_dynamic_analysis/)|[Splunk Attack Analyzer API](https://splunkbase.splunk.com/apps/#/search/Splunk Attack Analyzer API/product/soar)| Investigation |
| [Start Investigation](/playbooks/start_investigation/)| None | Investigation |
| [Threat Intel Investigate](/playbooks/threat_intel_investigate/)| None | Investigation |
| [TruSTAR Enrich Indicators](/playbooks/trustar_enrich_indicators/)|[TruSTAR](https://splunkbase.splunk.com/apps/#/search/TruSTAR/product/soar)| Investigation |
| [UrlScan IO Dynamic Analysis](/playbooks/urlscan_io_dynamic_analysis/)|[urlscan.io](https://splunkbase.splunk.com/apps/#/search/urlscan.io/product/soar)| Investigation |
| [VirusTotal V3 Dynamic Analysis](/playbooks/virustotal_v3_dynamic_analysis/)|[virustotal v3](https://splunkbase.splunk.com/apps/#/search/virustotal v3/product/soar)| Investigation |
| [VirusTotal v3 Identifier Reputation Analysis](/playbooks/virustotal_v3_identifier_reputation_analysis/)|[VirusTotal v3](https://splunkbase.splunk.com/apps/#/search/VirusTotal v3/product/soar)| Investigation |
| [Windows Defender ATP Identifier Activity Analysis](/playbooks/windows_defender_atp_identifier_activity_analysis/)|[Windows Defender ATP](https://splunkbase.splunk.com/apps/#/search/Windows Defender ATP/product/soar)| Investigation |
