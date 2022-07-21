---
title: "Active Directory Discovery"
last_modified_at: 2021-08-20
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

Monitor for activities and techniques associated with Discovery and Reconnaissance within with Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-20
- **Author**: Mauricio Velazco, Splunk
- **ID**: 8460679c-2b21-463e-b381-b813417c32f2

#### Narrative

Discovery consists of techniques an adversay uses to gain knowledge about an internal environment or network. These techniques provide adversaries with situational awareness and allows them to have the necessary information before deciding how to act or who/what to target next.\
Once an attacker obtains an initial foothold in an Active Directory environment, she is forced to engage in Discovery techniques in the initial phases of a breach to better understand and navigate the target network. Some examples include but are not limited to enumerating domain users, domain admins, computers, domain controllers, network shares, group policy objects, domain trusts, etc.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AdsiSearcher Account Discovery](/endpoint/adsisearcher_account_discovery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DSQuery Domain Discovery](/endpoint/dsquery_domain_discovery/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Account Discovery With Net App](/endpoint/domain_account_discovery_with_net_app/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Account Discovery with Dsquery](/endpoint/domain_account_discovery_with_dsquery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Account Discovery with Wmic](/endpoint/domain_account_discovery_with_wmic/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Controller Discovery with Nltest](/endpoint/domain_controller_discovery_with_nltest/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Controller Discovery with Wmic](/endpoint/domain_controller_discovery_with_wmic/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Dsquery](/endpoint/domain_group_discovery_with_dsquery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Net](/endpoint/domain_group_discovery_with_net/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Wmic](/endpoint/domain_group_discovery_with_wmic/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery with Adsisearcher](/endpoint/domain_group_discovery_with_adsisearcher/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Elevated Group Discovery With Net](/endpoint/elevated_group_discovery_with_net/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Elevated Group Discovery With Wmic](/endpoint/elevated_group_discovery_with_wmic/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Elevated Group Discovery with PowerView](/endpoint/elevated_group_discovery_with_powerview/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADDefaultDomainPasswordPolicy with Powershell](/endpoint/get_addefaultdomainpasswordpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADDefaultDomainPasswordPolicy with Powershell Script Block](/endpoint/get_addefaultdomainpasswordpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADUser with PowerShell](/endpoint/get_aduser_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADUser with PowerShell Script Block](/endpoint/get_aduser_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADUserResultantPasswordPolicy with Powershell](/endpoint/get_aduserresultantpasswordpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADUserResultantPasswordPolicy with Powershell Script Block](/endpoint/get_aduserresultantpasswordpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get DomainPolicy with Powershell](/endpoint/get_domainpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get DomainPolicy with Powershell Script Block](/endpoint/get_domainpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get DomainUser with PowerShell](/endpoint/get_domainuser_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get DomainUser with PowerShell Script Block](/endpoint/get_domainuser_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get WMIObject Group Discovery](/endpoint/get_wmiobject_group_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get WMIObject Group Discovery with Script Block Logging](/endpoint/get_wmiobject_group_discovery_with_script_block_logging/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get-DomainTrust with PowerShell](/endpoint/get-domaintrust_with_powershell/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get-DomainTrust with PowerShell Script Block](/endpoint/get-domaintrust_with_powershell_script_block/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get-ForestTrust with PowerShell](/endpoint/get-foresttrust_with_powershell/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get-ForestTrust with PowerShell Script Block](/endpoint/get-foresttrust_with_powershell_script_block/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdComputer with PowerShell](/endpoint/getadcomputer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdComputer with PowerShell Script Block](/endpoint/getadcomputer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdGroup with PowerShell](/endpoint/getadgroup_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdGroup with PowerShell Script Block](/endpoint/getadgroup_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetCurrent User with PowerShell](/endpoint/getcurrent_user_with_powershell/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetCurrent User with PowerShell Script Block](/endpoint/getcurrent_user_with_powershell_script_block/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainComputer with PowerShell](/endpoint/getdomaincomputer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainComputer with PowerShell Script Block](/endpoint/getdomaincomputer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainController with PowerShell](/endpoint/getdomaincontroller_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainController with PowerShell Script Block](/endpoint/getdomaincontroller_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainGroup with PowerShell](/endpoint/getdomaingroup_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainGroup with PowerShell Script Block](/endpoint/getdomaingroup_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetLocalUser with PowerShell](/endpoint/getlocaluser_with_powershell/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetLocalUser with PowerShell Script Block](/endpoint/getlocaluser_with_powershell_script_block/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetNetTcpconnection with PowerShell](/endpoint/getnettcpconnection_with_powershell/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetNetTcpconnection with PowerShell Script Block](/endpoint/getnettcpconnection_with_powershell_script_block/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject DS User with PowerShell](/endpoint/getwmiobject_ds_user_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject DS User with PowerShell Script Block](/endpoint/getwmiobject_ds_user_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject Ds Computer with PowerShell](/endpoint/getwmiobject_ds_computer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject Ds Computer with PowerShell Script Block](/endpoint/getwmiobject_ds_computer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject Ds Group with PowerShell](/endpoint/getwmiobject_ds_group_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject Ds Group with PowerShell Script Block](/endpoint/getwmiobject_ds_group_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject User Account with PowerShell](/endpoint/getwmiobject_user_account_with_powershell/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject User Account with PowerShell Script Block](/endpoint/getwmiobject_user_account_with_powershell_script_block/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Local Account Discovery With Wmic](/endpoint/local_account_discovery_with_wmic/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Local Account Discovery with Net](/endpoint/local_account_discovery_with_net/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [NLTest Domain Trust Discovery](/endpoint/nltest_domain_trust_discovery/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Net Localgroup Discovery](/endpoint/net_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Arp](/endpoint/network_connection_discovery_with_arp/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Net](/endpoint/network_connection_discovery_with_net/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Netstat](/endpoint/network_connection_discovery_with_netstat/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Discovery Using Route Windows App](/endpoint/network_discovery_using_route_windows_app/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Internet Connection Discovery](/tags/#internet-connection-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Password Policy Discovery with Net](/endpoint/password_policy_discovery_with_net/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell Get LocalGroup Discovery](/endpoint/powershell_get_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Get LocalGroup Discovery with Script Block Logging](/endpoint/powershell_get_localgroup_discovery_with_script_block_logging/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote System Discovery with Adsisearcher](/endpoint/remote_system_discovery_with_adsisearcher/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote System Discovery with Dsquery](/endpoint/remote_system_discovery_with_dsquery/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote System Discovery with Net](/endpoint/remote_system_discovery_with_net/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote System Discovery with Wmic](/endpoint/remote_system_discovery_with_wmic/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/serviceprincipalnames_discovery_with_powershell/) | [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/serviceprincipalnames_discovery_with_setspn/) | [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System User Discovery With Query](/endpoint/system_user_discovery_with_query/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System User Discovery With Whoami](/endpoint/system_user_discovery_with_whoami/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [User Discovery With Env Vars PowerShell](/endpoint/user_discovery_with_env_vars_powershell/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [User Discovery With Env Vars PowerShell Script Block](/endpoint/user_discovery_with_env_vars_powershell_script_block/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hidden Schedule Task Settings](/endpoint/windows_hidden_schedule_task_settings/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Linked Policies In ADSI Discovery](/endpoint/windows_linked_policies_in_adsi_discovery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Root Domain linked policies Discovery](/endpoint/windows_root_domain_linked_policies_discovery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wmic Group Discovery](/endpoint/wmic_group_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)
* [https://adsecurity.org/?p=2535](https://adsecurity.org/?p=2535)
* [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/)
* [https://attack.mitre.org/techniques/T1087/002/](https://attack.mitre.org/techniques/T1087/002/)
* [https://attack.mitre.org/techniques/T1087/003/](https://attack.mitre.org/techniques/T1087/003/)
* [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)
* [https://attack.mitre.org/techniques/T1201/](https://attack.mitre.org/techniques/T1201/)
* [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)
* [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)
* [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)
* [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)
* [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_discovery.yml) \| *version*: **1**