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
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Discovery and Reconnaissance within with Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-08-20
- **Author**: Mauricio Velazco, Splunk
- **ID**: 8460679c-2b21-463e-b381-b813417c32f2

#### Narrative

Discovery consists of techniques an adversay uses to gain knowledge about an internal environment or network. These techniques provide adversaries with situational awareness and allows them to have the necessary information before deciding how to act or who/what to target next.\
Once an attacker obtains an initial foothold in an Active Directory environment, she is forced to engage in Discovery techniques in the initial phases of a breach to better understand and navigate the target network. Some examples include but are not limited to enumerating domain users, domain admins, computers, domain controllers, network shares, group policy objects, domain trusts, etc.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AdsiSearcher Account Discovery](/endpoint/de7fcadc-04f3-11ec-a241-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DSQuery Domain Discovery](/endpoint/cc316032-924a-11eb-91a2-acde48001122/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Account Discovery With Net App](/endpoint/98f6a534-04c2-11ec-96b2-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Account Discovery with Dsquery](/endpoint/b1a8ce04-04c2-11ec-bea7-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Account Discovery with Wmic](/endpoint/383572e0-04c5-11ec-bdcc-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Controller Discovery with Nltest](/endpoint/41243735-89a7-4c83-bcdd-570aa78f00a1/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Controller Discovery with Wmic](/endpoint/64c7adaa-48ee-483c-b0d6-7175bc65e6cc/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Dsquery](/endpoint/f0c9d62f-a232-4edd-b17e-bc409fb133d4/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Net](/endpoint/f2f14ac7-fa81-471a-80d5-7eb65c3c7349/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Wmic](/endpoint/a87736a6-95cd-4728-8689-3c64d5026b3e/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery with Adsisearcher](/endpoint/089c862f-5f83-49b5-b1c8-7e4ff66560c7/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Elevated Group Discovery With Net](/endpoint/a23a0e20-0b1b-4a07-82e5-ec5f70811e7a/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Elevated Group Discovery With Wmic](/endpoint/3f6bbf22-093e-4cb4-9641-83f47b8444b6/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Elevated Group Discovery with PowerView](/endpoint/10d62950-0de5-4199-a710-cff9ea79b413/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADDefaultDomainPasswordPolicy with Powershell](/endpoint/36e46ebe-065a-11ec-b4c7-acde48001122/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADDefaultDomainPasswordPolicy with Powershell Script Block](/endpoint/1ff7ccc8-065a-11ec-91e4-acde48001122/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADUser with PowerShell](/endpoint/0b6ee3f4-04e3-11ec-a87d-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADUser with PowerShell Script Block](/endpoint/21432e40-04f4-11ec-b7e6-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADUserResultantPasswordPolicy with Powershell](/endpoint/8b5ef342-065a-11ec-b0fc-acde48001122/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get ADUserResultantPasswordPolicy with Powershell Script Block](/endpoint/737e1eb0-065a-11ec-921a-acde48001122/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get DomainPolicy with Powershell](/endpoint/b8f9947e-065a-11ec-aafb-acde48001122/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get DomainPolicy with Powershell Script Block](/endpoint/a360d2b2-065a-11ec-b0bf-acde48001122/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get DomainUser with PowerShell](/endpoint/9a5a41d6-04e7-11ec-923c-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get DomainUser with PowerShell Script Block](/endpoint/61994268-04f4-11ec-865c-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get WMIObject Group Discovery](/endpoint/5434f670-155d-11ec-8cca-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get WMIObject Group Discovery with Script Block Logging](/endpoint/69df7f7c-155d-11ec-a055-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get-DomainTrust with PowerShell](/endpoint/4fa7f846-054a-11ec-a836-acde48001122/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get-DomainTrust with PowerShell Script Block](/endpoint/89275e7e-0548-11ec-bf75-acde48001122/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get-ForestTrust with PowerShell](/endpoint/584f4884-0bf1-11ec-a5ec-acde48001122/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Get-ForestTrust with PowerShell Script Block](/endpoint/70fac80e-0bf1-11ec-9ba0-acde48001122/) | [Domain Trust Discovery](/tags/#domain-trust-discovery), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdComputer with PowerShell](/endpoint/c5a31f80-5888-4d81-9f78-1cc65026316e/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdComputer with PowerShell Script Block](/endpoint/a9a1da02-8e27-4bf7-a348-f4389c9da487/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdGroup with PowerShell](/endpoint/872e3063-0fc4-4e68-b2f3-f2b99184a708/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdGroup with PowerShell Script Block](/endpoint/e4c73d68-794b-468d-b4d0-dac1772bbae7/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetCurrent User with PowerShell](/endpoint/7eb9c3d5-c98c-4088-acc5-8240bad15379/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetCurrent User with PowerShell Script Block](/endpoint/80879283-c30f-44f7-8471-d1381f6d437a/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainComputer with PowerShell](/endpoint/ed550c19-712e-43f6-bd19-6f58f61b3a5e/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainComputer with PowerShell Script Block](/endpoint/f64da023-b988-4775-8d57-38e512beb56e/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainController with PowerShell](/endpoint/868ee0e4-52ab-484a-833a-6d85b7c028d0/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainController with PowerShell Script Block](/endpoint/676b600a-a94d-4951-b346-11329431e6c1/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainGroup with PowerShell](/endpoint/93c94be3-bead-4a60-860f-77ca3fe59903/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetDomainGroup with PowerShell Script Block](/endpoint/09725404-a44f-4ed3-9efa-8ed5d69e4c53/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetLocalUser with PowerShell](/endpoint/85fae8fa-0427-11ec-8b78-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetLocalUser with PowerShell Script Block](/endpoint/2e891cbe-0426-11ec-9c9c-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account), [PowerShell](/tags/#powershell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetNetTcpconnection with PowerShell](/endpoint/e02af35c-1de5-4afe-b4be-f45aba57272b/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetNetTcpconnection with PowerShell Script Block](/endpoint/091712ff-b02a-4d43-82ed-34765515d95d/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject DS User with PowerShell](/endpoint/22d3b118-04df-11ec-8fa3-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject DS User with PowerShell Script Block](/endpoint/fabd364e-04f3-11ec-b34b-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject Ds Computer with PowerShell](/endpoint/7141122c-3bc2-4aaa-ab3b-7a85a0bbefc3/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject Ds Computer with PowerShell Script Block](/endpoint/29b99201-723c-4118-847a-db2b3d3fb8ea/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject Ds Group with PowerShell](/endpoint/df275a44-4527-443b-b884-7600e066e3eb/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject Ds Group with PowerShell Script Block](/endpoint/67740bd3-1506-469c-b91d-effc322cc6e5/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject User Account with PowerShell](/endpoint/b44f6ac6-0429-11ec-87e9-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject User Account with PowerShell Script Block](/endpoint/640b0eda-0429-11ec-accd-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account), [PowerShell](/tags/#powershell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Local Account Discovery With Wmic](/endpoint/4902d7aa-0134-11ec-9d65-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Local Account Discovery with Net](/endpoint/5d0d4830-0133-11ec-bae3-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [NLTest Domain Trust Discovery](/endpoint/c3e05466-5f22-11eb-ae93-0242ac130002/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Net Localgroup Discovery](/endpoint/54f5201e-155b-11ec-a6e2-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Arp](/endpoint/ae008c0f-83bd-4ed4-9350-98d4328e15d2/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Net](/endpoint/640337e5-6e41-4b7f-af06-9d9eab5e1e2d/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Netstat](/endpoint/2cf5cc25-f39a-436d-a790-4857e5995ede/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Discovery Using Route Windows App](/endpoint/dd83407e-439f-11ec-ab8e-acde48001122/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Internet Connection Discovery](/tags/#internet-connection-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Password Policy Discovery with Net](/endpoint/09336538-065a-11ec-8665-acde48001122/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell Get LocalGroup Discovery](/endpoint/b71adfcc-155b-11ec-9413-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Get LocalGroup Discovery with Script Block Logging](/endpoint/d7c6ad22-155c-11ec-bb64-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote System Discovery with Adsisearcher](/endpoint/70803451-0047-4e12-9d63-77fa7eb8649c/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote System Discovery with Dsquery](/endpoint/9fb562f4-42f8-4139-8e11-a82edf7ed718/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote System Discovery with Net](/endpoint/9df16706-04a2-41e2-bbfe-9b38b34409d3/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote System Discovery with Wmic](/endpoint/d82eced3-b1dc-42ab-859e-a2fc98827359/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/13243068-2d38-11ec-8908-acde48001122/) | [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/ae8b3efc-2d2e-11ec-8b57-acde48001122/) | [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System User Discovery With Query](/endpoint/ad03bfcf-8a91-4bc2-a500-112993deba87/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System User Discovery With Whoami](/endpoint/894fc43e-6f50-47d5-a68b-ee9ee23e18f4/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [User Discovery With Env Vars PowerShell](/endpoint/0cdf318b-a0dd-47d7-b257-c621c0247de8/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [User Discovery With Env Vars PowerShell Script Block](/endpoint/77f41d9e-b8be-47e3-ab35-5776f5ec1d20/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Abnormal Object Access Activity](/endpoint/71b289db-5f2c-4c43-8256-8bf26ae7324a/) | [Account Discovery](/tags/#account-discovery), [Domain Account](/tags/#domain-account) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Privileged Object Access Activity](/endpoint/dc2f58bc-8cd2-4e51-962a-694b963acde0/) | [Account Discovery](/tags/#account-discovery), [Domain Account](/tags/#domain-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows File Share Discovery With Powerview](/endpoint/a44c0be1-d7ab-41e4-92fd-aa9af4fe232c/) | [Network Share Discovery](/tags/#network-share-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Find Domain Organizational Units with GetDomainOU](/endpoint/0ada2f82-b7af-40cc-b1d7-1e5985afcb4e/) | [Account Discovery](/tags/#account-discovery), [Domain Account](/tags/#domain-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Find Interesting ACL with FindInterestingDomainAcl](/endpoint/e4a96dfd-667a-4487-b942-ccef5a1e81e8/) | [Account Discovery](/tags/#account-discovery), [Domain Account](/tags/#domain-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Forest Discovery with GetForestDomain](/endpoint/a14803b2-4bd9-4c08-8b57-c37980edebe8/) | [Account Discovery](/tags/#account-discovery), [Domain Account](/tags/#domain-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Get Local Admin with FindLocalAdminAccess](/endpoint/d2988160-3ce9-4310-b59d-905334920cdd/) | [Account Discovery](/tags/#account-discovery), [Domain Account](/tags/#domain-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hidden Schedule Task Settings](/endpoint/0b730470-5fe8-4b13-93a7-fe0ad014d0cc/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Lateral Tool Transfer RemCom](/endpoint/e373a840-5bdc-47ef-b2fd-9cc7aaf387f0/) | [Lateral Tool Transfer](/tags/#lateral-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Linked Policies In ADSI Discovery](/endpoint/510ea428-4731-4d2f-8829-a28293e427aa/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView AD Access Control List Enumeration](/endpoint/39405650-c364-4e1e-a740-32a63ef042a6/) | [Domain Accounts](/tags/#domain-accounts), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Root Domain linked policies Discovery](/endpoint/80ffaede-1f12-49d5-a86e-b4b599b68b3c/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Create RemComSvc](/endpoint/0be4b5d6-c449-4084-b945-2392b519c33b/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Suspect Process With Authentication Traffic](/endpoint/953322db-128a-4ce9-8e89-56e039e33d98/) | [Account Discovery](/tags/#account-discovery), [Domain Account](/tags/#domain-account), [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wmic Group Discovery](/endpoint/83317b08-155b-11ec-8e00-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

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