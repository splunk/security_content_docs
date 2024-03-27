---
title: Response
layout: tag
author_profile: false
classes: wide
permalink: /playbooks/response/
sidebar:
  nav: "playbooks"
---

| Name    | SOAR App   | D3FEND      | Use Case    |
| --------| ---------- | ----------- | ----------- |
| [AD LDAP Account Unlocking](/playbooks/ad_ldap_account_unlocking/)| [AD LDAP](https://splunkbase.splunk.com/apps?keyword=ad+ldap&filters=product%3Asoar)| | |
| [AWS Disable User Accounts](/playbooks/aws_disable_user_accounts/)| [AWS IAM](https://splunkbase.splunk.com/apps?keyword=aws+iam&filters=product%3Asoar)| | |
| [AWS IAM Account Unlocking](/playbooks/aws_iam_account_unlocking/)| [AWS IAM](https://splunkbase.splunk.com/apps?keyword=aws+iam&filters=product%3Asoar)| [Restore User Account Access](https://d3fend.mitre.org/technique/d3f:RestoreUserAccountAccess)| |
| [Active Directory Enable Account Dispatch](/playbooks/active_directory_enable_account_dispatch/)| [AD LDAP](https://splunkbase.splunk.com/apps?keyword=ad+ldap&filters=product%3Asoar), [Azure AD Graph](https://splunkbase.splunk.com/apps?keyword=azure+ad+graph&filters=product%3Asoar), [AWS IAM](https://splunkbase.splunk.com/apps?keyword=aws+iam&filters=product%3Asoar)| | |
| [Active Directory Reset password](/playbooks/active_directory_reset_password/)| [AD LDAP](https://splunkbase.splunk.com/apps?keyword=ad+ldap&filters=product%3Asoar)| | |
| [Azure AD Account Unlocking](/playbooks/azure_ad_account_unlocking/)| [Azure AD Graph](https://splunkbase.splunk.com/apps?keyword=azure+ad+graph&filters=product%3Asoar)| [Restore User Account Access](https://d3fend.mitre.org/technique/d3f:RestoreUserAccountAccess)| |
| [Block Indicators](/playbooks/block_indicators/)| [Palo Alto Networks Firewall](https://splunkbase.splunk.com/apps?keyword=palo+alto+networks+firewall&filters=product%3Asoar), [Carbon Black Response](https://splunkbase.splunk.com/apps?keyword=carbon+black+response&filters=product%3Asoar), [Cisco Umbrella](https://splunkbase.splunk.com/apps?keyword=cisco+umbrella&filters=product%3Asoar)| | |
| [Cisco Umbrella DNS Denylisting](/playbooks/cisco_umbrella_dns_denylisting/)| [Cisco Umbrella](https://splunkbase.splunk.com/apps?keyword=cisco+umbrella&filters=product%3Asoar)| [DNS Denylisting](https://d3fend.mitre.org/technique/d3f:DNSDenylisting)| [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [Crowdstrike Malware Triage](/playbooks/crowdstrike_malware_triage/)| [CrowdStrike OAuth API](https://splunkbase.splunk.com/apps?keyword=crowdstrike+oauth+api&filters=product%3Asoar)| | |
| [DNS Denylisting Dispatch](/playbooks/dns_denylisting_dispatch/)| | [DNS Denylisting](https://d3fend.mitre.org/technique/d3f:DNSDenylisting)| [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [Delete Detected Files](/playbooks/delete_detected_files/)| [Windows Remote Management](https://splunkbase.splunk.com/apps?keyword=windows+remote+management&filters=product%3Asoar)| | |
| [Email Notification for Malware](/playbooks/email_notification_for_malware/)| [VirusTotal](https://splunkbase.splunk.com/apps?keyword=virustotal&filters=product%3Asoar), [WildFire](https://splunkbase.splunk.com/apps?keyword=wildfire&filters=product%3Asoar), [Carbon Black Response](https://splunkbase.splunk.com/apps?keyword=carbon+black+response&filters=product%3Asoar), [SMTP](https://splunkbase.splunk.com/apps?keyword=smtp&filters=product%3Asoar)| | |
| [G Suite for Gmail Message Eviction](/playbooks/g_suite_for_gmail_message_eviction/)| [G Suite for GMail](https://splunkbase.splunk.com/apps?keyword=g+suite+for+gmail&filters=product%3Asoar)| [Email Removal](https://d3fend.mitre.org/technique/d3f:EmailRemoval)| [Phishing](/playbooks/phishing)|
| [G Suite for Gmail Search and Purge](/playbooks/g_suite_for_gmail_search_and_purge/)| [G Suite for GMail](https://splunkbase.splunk.com/apps?keyword=g+suite+for+gmail&filters=product%3Asoar)| [Email Removal](https://d3fend.mitre.org/technique/d3f:EmailRemoval), [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Phishing](/playbooks/phishing)|
| [Internal Host SSH Log4j Response](/playbooks/internal_host_ssh_log4j_response/)| [SSH](https://splunkbase.splunk.com/apps?keyword=ssh&filters=product%3Asoar)| | |
| [Internal Host WinRM Response](/playbooks/internal_host_winrm_response/)| [Windows Remote Management](https://splunkbase.splunk.com/apps?keyword=windows+remote+management&filters=product%3Asoar)| | |
| [Log4j Respond](/playbooks/log4j_respond/)| | | |
| [MS Graph for Office 365 Message Eviction](/playbooks/ms_graph_for_office_365_message_eviction/)| [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)| [Email Removal](https://d3fend.mitre.org/technique/d3f:EmailRemoval)| [Phishing](/playbooks/phishing)|
| [MS Graph for Office 365 Message Restore](/playbooks/ms_graph_for_office_365_message_restore/)| [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)| [Restore Email](https://d3fend.mitre.org/technique/d3f:RestoreEmail)| [Phishing](/playbooks/phishing)|
| [MS Graph for Office365 Search and Purge](/playbooks/ms_graph_for_office365_search_and_purge/)| [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)| [Email Removal](https://d3fend.mitre.org/technique/d3f:EmailRemoval), [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis)| [Phishing](/playbooks/phishing)|
| [MS Graph for Office365 Search and Restore](/playbooks/ms_graph_for_office365_search_and_restore/)| [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)| [Restore Email](https://d3fend.mitre.org/technique/d3f:RestoreEmail)| [Phishing](/playbooks/phishing)|
| [Malware Hunt and Contain](/playbooks/malware_hunt_and_contain/)| [LDAP](https://splunkbase.splunk.com/apps?keyword=ldap&filters=product%3Asoar), [ServiceNow](https://splunkbase.splunk.com/apps?keyword=servicenow&filters=product%3Asoar), [Carbon Black Response](https://splunkbase.splunk.com/apps?keyword=carbon+black+response&filters=product%3Asoar), [VirusTotal](https://splunkbase.splunk.com/apps?keyword=virustotal&filters=product%3Asoar)| | |
| [Panorama Outbound Traffic Filtering](/playbooks/panorama_outbound_traffic_filtering/)| [Panorama](https://splunkbase.splunk.com/apps?keyword=panorama&filters=product%3Asoar)| [Outbound Traffic Filtering](https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering)| [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [Ransomware Investigate and Contain](/playbooks/ransomware_investigate_and_contain/)| [Carbon Black Response](https://splunkbase.splunk.com/apps?keyword=carbon+black+response&filters=product%3Asoar), [LDAP](https://splunkbase.splunk.com/apps?keyword=ldap&filters=product%3Asoar), [Palo Alto Networks Firewall](https://splunkbase.splunk.com/apps?keyword=palo+alto+networks+firewall&filters=product%3Asoar), [WildFire](https://splunkbase.splunk.com/apps?keyword=wildfire&filters=product%3Asoar), [Cylance](https://splunkbase.splunk.com/apps?keyword=cylance&filters=product%3Asoar)| | |
| [Risk Notable Block Indicators](/playbooks/risk_notable_block_indicators/)| | | |
| [Risk Notable Mitigate](/playbooks/risk_notable_mitigate/)| | | |
| [Risk Notable Protect Assets and Users](/playbooks/risk_notable_protect_assets_and_users/)| | | |
| [Risk Notable Review Indicators](/playbooks/risk_notable_review_indicators/)| | | |
| [Risk Notable Verdict](/playbooks/risk_notable_verdict/)| | | |
| [URL Outbound Traffic Filtering Dispatch](/playbooks/url_outbound_traffic_filtering_dispatch/)| | [Outbound Traffic Filtering](https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering)| [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|
| [ZScaler Outbound Traffic Filtering](/playbooks/zscaler_outbound_traffic_filtering/)| [Zscaler](https://splunkbase.splunk.com/apps?keyword=zscaler&filters=product%3Asoar)| | [Phishing](/playbooks/phishing), [Endpoint](/playbooks/endpoint)|