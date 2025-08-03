# 🛡️ Active Directory Attack Techniques (Red Team Edition)

This document provides a detailed walkthrough of **25 real-world Active Directory attack techniques**, optimized for **CRTP**, **OSCP**, and stealth-focused **Red Team operations**.

---

## ✅ Features

- 🔐 Realistic AD attacks (AS-REP Roasting, Kerberoasting, DCSync, etc.)
- 🧠 Understand how each technique works under the hood
- 🛠 Tools and usage examples
- 🕵️‍♂️ Red Team **stealth recommendations** for quiet execution
- 📥 Downloadable HTML [Interactive Checklist](./CRTP_OSCP_AD_CheckList.html) available

---

## 📑 Table of Contents
- [1. AS-REP Roasting](#as-rep-roasting)
- [2. Kerberoasting](#kerberoasting)
- [3. Pass-the-Hash (PtH)](#pass-the-hash-%28pth%29)
- [4. Pass-the-Ticket (PtT)](#pass-the-ticket-%28ptt%29)
- [5. DCSync Attack](#dcsync-attack)
- [6. Unconstrained Delegation](#unconstrained-delegation)
- [7. Constrained Delegation](#constrained-delegation)
- [8. Resource-Based Constrained Delegation (RBCD)](#resource-based-constrained-delegation-%28rbcd%29)
- [9. Silver Ticket](#silver-ticket)
- [10. Golden Ticket](#golden-ticket)
- [11. NTDS.dit Dump](#ntdsdit-dump)
- [12. GPP Passwords](#gpp-passwords)
- [13. LAPS Dumping](#laps-dumping)
- [14. AdminSDHolder Abuse](#adminsdholder-abuse)
- [15. ACL Abuse](#acl-abuse)
- [16. Printer Spooler Bug](#printer-spooler-bug)
- [17. Shadow Credentials](#shadow-credentials)
- [18. Certificate Template Escalation (ESC1)](#certificate-template-escalation-%28esc1%29)
- [19. Service Unquoted Path Abuse](#service-unquoted-path-abuse)
- [20. RDP Hijack](#rdp-hijack)
- [21. SAM & SYSTEM Hive Dump](#sam-%26-system-hive-dump)
- [22. LSA Secrets Dump](#lsa-secrets-dump)
- [23. RID Cycling](#rid-cycling)
- [24. Token Impersonation](#token-impersonation)
- [25. WMI Lateral Movement](#wmi-lateral-movement)
- [26. ADCS ESC1: Misconfigured Certificate Template](#adcs-esc1%3A-misconfigured-certificate-template)
- [27. ADCS ESC8: NTLM Relay to Web Enrollment](#adcs-esc8%3A-ntlm-relay-to-web-enrollment)
- [28. PetitPotam + ADCS (EFSRPC Coercion)](#petitpotam-%2B-adcs-%28efsrpc-coercion%29)
- [29. AdminSDHolder Persistence](#adminsdholder-persistence)
- [30. SID Filtering Bypass](#sid-filtering-bypass)
- [31. LDAP ACL Enumeration & Abuse](#ldap-acl-enumeration-%26-abuse)
- [32. Printer Bug (MS-RPRN Coercion)](#printer-bug-%28ms-rprn-coercion%29)
- [33. Unusual SPN Registration for Lateral Movement](#unusual-spn-registration-for-lateral-movement)
- [34. ESC2: Template with Weak ACL](#esc2%3A-template-with-weak-acl)
- [35. ESC3: Enrollable by Low-Priv Group](#esc3%3A-enrollable-by-low-priv-group)
- [36. ESC4: Manager Approval Misuse](#esc4%3A-manager-approval-misuse)
- [37. ESC5: Enroll as Machine Template](#esc5%3A-enroll-as-machine-template)
- [38. ESC6: Authenticated Users Can Enroll](#esc6%3A-authenticated-users-can-enroll)
- [39. ESC7: Vulnerable Unused Template](#esc7%3A-vulnerable-unused-template)
- [40. DCSync via GenericAll / Replication Rights](#dcsync-via-genericall--replication-rights)
- [41. Abusing GenericWrite on User Object](#abusing-genericwrite-on-user-object)
- [42. Overpass-the-Hash (Pass-the-Key)](#overpass-the-hash-%28pass-the-key%29)
- [43. RBCD via AddAllowedToAct (ACL Abuse)](#rbcd-via-addallowedtoact-%28acl-abuse%29)
- [44. Abusing Resource-Based Constrained Delegation (No Pre-auth)](#abusing-resource-based-constrained-delegation-%28no-pre-auth%29)
- [45. DCShadow Attack](#dcshadow-attack)
- [46. Golden Ticket Attack](#golden-ticket-attack)
- [47. Skeleton Key Attack](#skeleton-key-attack)
- [48. SIDHistory Injection](#sidhistory-injection)
- [49. AdminSDHolder Abuse](#adminsdholder-abuse)
- [50. Unconstrained Delegation Abuse](#unconstrained-delegation-abuse)
- [51. Kerberoasting with AES Keys](#kerberoasting-with-aes-keys)
- [52. Printer Bug + RBCD](#printer-bug-%2B-rbcd)
- [53. Kerberos SID Filtering Bypass](#kerberos-sid-filtering-bypass)
- [54. AS-REP Roasting (AES Variant)](#as-rep-roasting-%28aes-variant%29)
- [55. DNSAdmin to DC Compromise](#dnsadmin-to-dc-compromise)
- [56. Abusing ACL on GPO](#abusing-acl-on-gpo)
- [57. Shadow Credentials (Key Credential Link Attack)](#shadow-credentials-%28key-credential-link-attack%29)
- [58. Exchange PrivEsc via WriteDacl](#exchange-privesc-via-writedacl)
- [59. ReadGMSAPassword for Privilege Escalation](#readgmsapassword-for-privilege-escalation)
- [60. Kerberos Delegation Loop](#kerberos-delegation-loop)
- [61. Abuse Service Principal Name (SPN) via Resource-based Constrained Delegation](#abuse-service-principal-name-%28spn%29-via-resource-based-constrained-delegation)
- [62. Malicious GPO Deployment](#malicious-gpo-deployment)
- [63. Kerberos Constrained Delegation (KCD) Abuse](#kerberos-constrained-delegation-%28kcd%29-abuse)
- [64. Unquoted Service Path Privilege Escalation](#unquoted-service-path-privilege-escalation)

---



## 📋 Attack Descriptions


<a name="as-rep-roasting"></a>
<details>
  <summary><strong>1. AS-REP Roasting</strong></summary>

- **Purpose**: Offline cracking of user password hash  
- **Functionality**: Kerberos allows unauthenticated ticket requests for users with DONT_REQ_PREAUTH  
- **Why It's Vulnerable**: No pre-auth required, so TGT encrypted with weak password hash can be cracked  
- **How to Test**: Use GetNPUsers.py or Rubeus to extract hashes; crack using hashcat  
- **Tools**: Impacket, Rubeus, hashcat  
- **Stealth Tips**: Use known usernames only; avoid brute-forcing; low log footprint  

</details>


<a name="kerberoasting"></a>
<details>
  <summary><strong>2. Kerberoasting</strong></summary>

- **Purpose**: Offline password cracking of service accounts  
- **Functionality**: Any user can request a service ticket (TGS) for SPN accounts  
- **Why It's Vulnerable**: Service ticket is encrypted with NTLM hash of the service account  
- **How to Test**: Use Rubeus or GetUserSPNs.py to extract TGS and crack  
- **Tools**: Rubeus, Impacket, hashcat  
- **Stealth Tips**: Minimize TGS requests; monitor Event ID 4769  

</details>


<a name="pass-the-hash-%28pth%29"></a>
<details>
  <summary><strong>3. Pass-the-Hash (PtH)</strong></summary>

- **Purpose**: Authenticate without knowing plaintext password  
- **Functionality**: Windows allows authentication using NTLM hashes  
- **Why It's Vulnerable**: Captured NTLM hashes can be reused in SMB/WinRM  
- **How to Test**: Use evil-winrm or wmiexec with hash  
- **Tools**: Mimikatz, Evil-WinRM, CrackMapExec  
- **Stealth Tips**: Use non-noisy protocols (e.g., WinRM); avoid failed auth  

</details>


<a name="pass-the-ticket-%28ptt%29"></a>
<details>
  <summary><strong>4. Pass-the-Ticket (PtT)</strong></summary>

- **Purpose**: Reuse Kerberos ticket for lateral movement  
- **Functionality**: Kerberos TGTs and TGSs are valid for hours  
- **Why It's Vulnerable**: Extracted tickets can be reused from other machines  
- **How to Test**: Use Rubeus to inject TGT (.kirbi) into current session  
- **Tools**: Rubeus, Mimikatz  
- **Stealth Tips**: Use existing ticket times; avoid creating new tickets  

</details>


<a name="dcsync-attack"></a>
<details>
  <summary><strong>5. DCSync Attack</strong></summary>

- **Purpose**: Dump password hashes from DC without LSASS access  
- **Functionality**: Accounts with Replication rights can request user secrets  
- **Why It's Vulnerable**: Rights like Replicating Directory Changes allow this access  
- **How to Test**: Use Mimikatz lsadump::dcsync /user:Administrator  
- **Tools**: Mimikatz, secretsdump.py  
- **Stealth Tips**: Limit to 1 request; Event ID 4662 if auditing enabled  

</details>


<a name="unconstrained-delegation"></a>
<details>
  <summary><strong>6. Unconstrained Delegation</strong></summary>

- **Purpose**: Steal TGTs from incoming users  
- **Functionality**: Delegated systems cache TGTs of authenticating users in memory  
- **Why It's Vulnerable**: Attacker can extract TGTs from memory if they control such a host  
- **How to Test**: Dump LSASS on delegated host after privileged user login  
- **Tools**: Procdump, Mimikatz, Rubeus  
- **Stealth Tips**: Dump only after login; avoid repeated access  

</details>


<a name="constrained-delegation"></a>
<details>
  <summary><strong>7. Constrained Delegation</strong></summary>

- **Purpose**: Impersonate users to a specific service  
- **Functionality**: Service accounts can impersonate to target SPNs using user’s TGT  
- **Why It's Vulnerable**: Abuse the delegation to impersonate DA to a specific service  
- **How to Test**: Use S4U modules in Rubeus or Impacket to impersonate  
- **Tools**: Rubeus, Impacket  
- **Stealth Tips**: Limit usage; target non-logged services  

</details>


<a name="resource-based-constrained-delegation-%28rbcd%29"></a>
<details>
  <summary><strong>8. Resource-Based Constrained Delegation (RBCD)</strong></summary>

- **Purpose**: Gain access to services by controlling delegation  
- **Functionality**: AD allows specifying which accounts can delegate to a service  
- **Why It's Vulnerable**: Create a machine account and assign it to RBCD of a target  
- **How to Test**: Use PowerView or Set-ADComputer to set msDS-AllowedToActOnBehalfOfOtherIdentity  
- **Tools**: Rubeus, PowerView, Impacket  
- **Stealth Tips**: Prefer machine account reuse; avoid excessive LDAP changes  

</details>


<a name="silver-ticket"></a>
<details>
  <summary><strong>9. Silver Ticket</strong></summary>

- **Purpose**: Access services without contacting DC  
- **Functionality**: TGS can be forged using service account’s NTLM hash  
- **Why It's Vulnerable**: Use hash to forge TGS with Mimikatz or Rubeus  
- **How to Test**: Create TGS for service and inject it  
- **Tools**: Mimikatz, Rubeus  
- **Stealth Tips**: Avoid Kerberos event logs; direct access to service  

</details>


<a name="golden-ticket"></a>
<details>
  <summary><strong>10. Golden Ticket</strong></summary>

- **Purpose**: Forge TGT and impersonate any user  
- **Functionality**: If KRBTGT hash is known, you can forge valid TGTs  
- **Why It's Vulnerable**: Use Mimikatz to forge TGT with domain SID and KRBTGT hash  
- **How to Test**: Inject ticket into session and access DC  
- **Tools**: Mimikatz  
- **Stealth Tips**: Limit validity; cleanup injected tickets  

</details>


<a name="ntdsdit-dump"></a>
<details>
  <summary><strong>11. NTDS.dit Dump</strong></summary>

- **Purpose**: Extract all AD user hashes  
- **Functionality**: NTDS.dit stores all password hashes for domain  
- **Why It's Vulnerable**: Access DC and dump NTDS.dit and SYSTEM hive  
- **How to Test**: Use secretsdump.py or DSInternals to parse  
- **Tools**: ntdsutil, secretsdump.py, DSInternals  
- **Stealth Tips**: Use VSS to avoid detection  

</details>


<a name="gpp-passwords"></a>
<details>
  <summary><strong>12. GPP Passwords</strong></summary>

- **Purpose**: Recover local admin creds from SYSVOL  
- **Functionality**: Legacy Group Policy XML files stored with encrypted passwords  
- **Why It's Vulnerable**: Locate Groups.xml and decrypt cpassword value  
- **How to Test**: Search SYSVOL for GPP files, use gpp-decrypt  
- **Tools**: GPPDecrypt, SharpGPP  
- **Stealth Tips**: Read-only operation; no log generation  

</details>


<a name="laps-dumping"></a>
<details>
  <summary><strong>13. LAPS Dumping</strong></summary>

- **Purpose**: Retrieve LAPS-managed local passwords  
- **Functionality**: Passwords stored in AD attribute ms-MCS-AdmPwd  
- **Why It's Vulnerable**: Query the attribute using a user with read rights  
- **How to Test**: Get-ADComputer -Property ms-MCS-AdmPwd  
- **Tools**: PowerView, SharpLAPS  
- **Stealth Tips**: Check permissions before; no change needed  

</details>


<a name="adminsdholder-abuse"></a>
<details>
  <summary><strong>14. AdminSDHolder Abuse</strong></summary>

- **Purpose**: Persistent admin privilege via ACLs  
- **Functionality**: ACLs on AdminSDHolder apply to all protected users  
- **Why It's Vulnerable**: Modify AdminSDHolder DACL to grant access to attacker  
- **How to Test**: Use PowerView to modify ACLs  
- **Tools**: PowerView, ADACLScanner  
- **Stealth Tips**: Delay abuse to maintenance windows  

</details>


<a name="acl-abuse"></a>
<details>
  <summary><strong>15. ACL Abuse</strong></summary>

- **Purpose**: Escalate privileges using misconfigured permissions  
- **Functionality**: GenericWrite, WriteOwner etc. on high-priv objects  
- **Why It's Vulnerable**: Identify and exploit access rights  
- **How to Test**: Use BloodHound to identify privilege escalation paths  
- **Tools**: BloodHound, PowerView  
- **Stealth Tips**: Exploit only one path at a time  

</details>


<a name="printer-spooler-bug"></a>
<details>
  <summary><strong>16. Printer Spooler Bug</strong></summary>

- **Purpose**: Force authentication to attacker host  
- **Functionality**: Spooler service allows remote connections and auth triggers  
- **Why It's Vulnerable**: Trigger authentication using SpoolSample or PrinterBug  
- **How to Test**: Redirect auth to NTLM relay listener  
- **Tools**: PrinterBug, Responder, Impacket  
- **Stealth Tips**: Disable after use; triggers events  

</details>


<a name="shadow-credentials"></a>
<details>
  <summary><strong>17. Shadow Credentials</strong></summary>

- **Purpose**: Persist via malicious certificate mapping  
- **Functionality**: UserCertificates attribute can store arbitrary certs  
- **Why It's Vulnerable**: Inject malicious cert, then use it for impersonation  
- **How to Test**: Use Whisker or Certipy to inject and authenticate  
- **Tools**: Certipy, Whisker  
- **Stealth Tips**: Remove cert after use  

</details>


<a name="certificate-template-escalation-%28esc1%29"></a>
<details>
  <summary><strong>18. Certificate Template Escalation (ESC1)</strong></summary>

- **Purpose**: Enroll as admin via misconfigured template  
- **Functionality**: Weak ACLs on template allow unauthorized enrollment  
- **Why It's Vulnerable**: Request certificate with higher privilege permissions  
- **How to Test**: Use Certify or Certipy to list and exploit templates  
- **Tools**: Certify, Certipy  
- **Stealth Tips**: Use short-lived certs, cleanup enrollment  

</details>


<a name="service-unquoted-path-abuse"></a>
<details>
  <summary><strong>19. Service Unquoted Path Abuse</strong></summary>

- **Purpose**: Privilege escalation to SYSTEM  
- **Functionality**: Windows services with unquoted paths allow writing malicious exe  
- **Why It's Vulnerable**: Replace exe in writable path and restart service  
- **How to Test**: Use sc qc and accesschk to verify permissions  
- **Tools**: accesschk, sc.exe  
- **Stealth Tips**: Time replacement during service downtime  

</details>


<a name="rdp-hijack"></a>
<details>
  <summary><strong>20. RDP Hijack</strong></summary>

- **Purpose**: Intercept RDP session of DA  
- **Functionality**: Logged-in sessions can be hijacked via TS API  
- **Why It's Vulnerable**: Detect active RDP session and take over  
- **How to Test**: Use tscon.exe to connect to existing session  
- **Tools**: tscon.exe  
- **Stealth Tips**: Only works locally; use with caution  

</details>


<a name="sam-%26-system-hive-dump"></a>
<details>
  <summary><strong>21. SAM & SYSTEM Hive Dump</strong></summary>

- **Purpose**: Dump local hashes from registry  
- **Functionality**: SAM & SYSTEM registry hives store local account credentials  
- **Why It's Vulnerable**: Export hives and parse offline  
- **How to Test**: Use reg.exe or Volume Shadow Copy  
- **Tools**: reg.exe, secretsdump.py  
- **Stealth Tips**: Use shadow copy to avoid lock issues  

</details>


<a name="lsa-secrets-dump"></a>
<details>
  <summary><strong>22. LSA Secrets Dump</strong></summary>

- **Purpose**: Retrieve stored service creds  
- **Functionality**: LSA stores secrets like service passwords and cached creds  
- **Why It's Vulnerable**: Dump registry and parse using tools  
- **How to Test**: Export HKLM\SECURITY and SYSTEM  
- **Tools**: secretsdump.py, mimikatz  
- **Stealth Tips**: Requires SYSTEM; avoid writing to disk  

</details>


<a name="rid-cycling"></a>
<details>
  <summary><strong>23. RID Cycling</strong></summary>

- **Purpose**: Enumerate users by RID brute-force  
- **Functionality**: SAMR protocol allows RID lookup  
- **Why It's Vulnerable**: Cycle RIDs from 500–1500 to find valid users  
- **How to Test**: Use rpcclient or crackmapexec  
- **Tools**: rpcclient, CME  
- **Stealth Tips**: Limit RID range; avoid excessive RPC calls  

</details>


<a name="token-impersonation"></a>
<details>
  <summary><strong>24. Token Impersonation</strong></summary>

- **Purpose**: Steal tokens from other sessions  
- **Functionality**: Access tokens can be duplicated from running processes  
- **Why It's Vulnerable**: Enumerate and impersonate tokens via Mimikatz  
- **How to Test**: token::list and token::elevate  
- **Tools**: Mimikatz  
- **Stealth Tips**: Only do on high-integrity sessions  

</details>


<a name="wmi-lateral-movement"></a>
<details>
  <summary><strong>25. WMI Lateral Movement</strong></summary>

- **Purpose**: Execute commands on remote hosts  
- **Functionality**: WMI allows remote management access  
- **Why It's Vulnerable**: Invoke-WmiMethod or wmiexec.py for command execution  
- **How to Test**: Execute payload via WMI  
- **Tools**: PowerShell, wmiexec.py  
- **Stealth Tips**: Avoid noisy payloads; use minimal commands  

</details>

<a name="adcs-esc1%3A-misconfigured-certificate-template"></a>
<details>
  <summary><strong>26. ADCS ESC1: Misconfigured Certificate Template</strong></summary>

- **Purpose**: Impersonate users via template that allows user-supplied subjects  
- **Functionality**: ENROLLEE_SUPPLIES_SUBJECT enabled with low auth  
- **Why It's Vulnerable**: Request cert with target UPN  
- **How to Test**: Use cert to authenticate via PKINIT  
- **Tools**: Certify, ForgeCert, Rubeus  
- **Stealth Tips**: Target mid-tier accounts; avoid detection  

</details>
<a name="adcs-esc8%3A-ntlm-relay-to-web-enrollment"></a>
<details>
  <summary><strong>27. ADCS ESC8: NTLM Relay to Web Enrollment</strong></summary>

- **Purpose**: Relay NTLM to issue certificates  
- **Functionality**: Web Enrollment allows unsigned NTLM negotiation  
- **Why It's Vulnerable**: Relay auth to ADCS endpoint  
- **How to Test**: Request cert and impersonate high-priv user  
- **Tools**: Impacket (ntlmrelayx), Certify  
- **Stealth Tips**: Clean up certs and log entries  

</details>
<a name="petitpotam-%2B-adcs-%28efsrpc-coercion%29"></a>
<details>
  <summary><strong>28. PetitPotam + ADCS (EFSRPC Coercion)</strong></summary>

- **Purpose**: Force machine auth via EFSRPC and relay to ADCS  
- **Functionality**: EFSRPC coerce NTLM auth to relay point  
- **Why It's Vulnerable**: Trigger EFSRPC coercion using PetitPotam  
- **How to Test**: Relay to ADCS and request certificate  
- **Tools**: PetitPotam, ntlmrelayx, Certify  
- **Stealth Tips**: Use selectively; avoid excessive noise  

</details>
<a name="adminsdholder-persistence"></a>
<details>
  <summary><strong>29. AdminSDHolder Persistence</strong></summary>

- **Purpose**: Persistent control via ACL on AdminSDHolder  
- **Functionality**: AdminSDHolder sets ACLs on protected users  
- **Why It's Vulnerable**: Modify AdminSDHolder ACLs  
- **How to Test**: Get control over Domain Admins periodically  
- **Tools**: PowerView, Set-ACL  
- **Stealth Tips**: Delay changes and remove traces  

</details>
<a name="sid-filtering-bypass"></a>
<details>
  <summary><strong>30. SID Filtering Bypass</strong></summary>

- **Purpose**: Impersonate foreign domain users via SIDHistory  
- **Functionality**: Poorly filtered trusts allow SID injection  
- **Why It's Vulnerable**: Create golden ticket with extra SIDs  
- **How to Test**: Access resources in trusted domain  
- **Tools**: Mimikatz  
- **Stealth Tips**: Limit SID usage; avoid well-known SIDs  

</details>
<a name="ldap-acl-enumeration-%26-abuse"></a>
<details>
  <summary><strong>31. LDAP ACL Enumeration & Abuse</strong></summary>

- **Purpose**: Find and abuse weak ACLs on AD objects  
- **Functionality**: Misconfigured ACLs allow privilege escalation  
- **Why It's Vulnerable**: Enumerate using PowerView/BloodHound  
- **How to Test**: Exploit RBCD, DCSync, or object control  
- **Tools**: BloodHound, PowerView, SharpHound  
- **Stealth Tips**: Prefer low-visibility objects; clean up after  

</details>
<a name="printer-bug-%28ms-rprn-coercion%29"></a>
<details>
  <summary><strong>32. Printer Bug (MS-RPRN Coercion)</strong></summary>

- **Purpose**: Force system to auth to attacker listener  
- **Functionality**: Spooler forces auth to remote UNC path  
- **Why It's Vulnerable**: Trigger print request to attacker's SMB  
- **How to Test**: Relay or capture machine hash  
- **Tools**: SpoolSample, Impacket  
- **Stealth Tips**: Limit usage; avoid DoS on printer services  

</details>
<a name="unusual-spn-registration-for-lateral-movement"></a>
<details>
  <summary><strong>33. Unusual SPN Registration for Lateral Movement</strong></summary>

- **Purpose**: Use fake SPNs to capture TGS or redirect auth  
- **Functionality**: SPNs can be registered by users with write access  
- **Why It's Vulnerable**: Register SPN with setspn or script  
- **How to Test**: Wait for TGS request and roast/capture  
- **Tools**: setspn, PowerView  
- **Stealth Tips**: Use misleading names; monitor SPN alerts  

</details>
<a name="esc2%3A-template-with-weak-acl"></a>
<details>
  <summary><strong>34. ESC2: Template with Weak ACL</strong></summary>

- **Purpose**: Low-privilege users can modify the certificate template permissions.  
- **Functionality**: Templates with weak DACLs can be edited to allow elevation.  
- **Why It's Vulnerable**: Enumerate template permissions with Certify, then modify ACL to allow enrollment.  
- **How to Test**: Use Certify to identify and exploit weak ACLs.  
- **Tools**: Certify, PowerView  
- **Stealth Tips**: Use minimal DACL changes and remove custom ACEs post-exploitation.  

</details>
<a name="esc3%3A-enrollable-by-low-priv-group"></a>
<details>
  <summary><strong>35. ESC3: Enrollable by Low-Priv Group</strong></summary>

- **Purpose**: Template allows members of a low-privileged group to enroll certificates.  
- **Functionality**: Misconfiguration allows wide group enrollment without tight control.  
- **Why It's Vulnerable**: Use Certify to identify templates accessible by groups like 'Domain Users'.  
- **How to Test**: Request certs for target users using ForgeCert or Certify.  
- **Tools**: Certify, ForgeCert, Rubeus  
- **Stealth Tips**: Do not request certs for Domain Admins directly.  

</details>
<a name="esc4%3A-manager-approval-misuse"></a>
<details>
  <summary><strong>36. ESC4: Manager Approval Misuse</strong></summary>

- **Purpose**: Templates require manager approval but attacker can set themselves as manager.  
- **Functionality**: Manager approval is not properly enforced; attackers can self-approve.  
- **Why It's Vulnerable**: Set attacker account as manager of target object, then enroll.  
- **How to Test**: Use ADUC or PowerShell to set manager attribute, then Certify.  
- **Tools**: PowerShell, Certify  
- **Stealth Tips**: Ensure quick usage before manager attribute is reset by policies.  

</details>
<a name="esc5%3A-enroll-as-machine-template"></a>
<details>
  <summary><strong>37. ESC5: Enroll as Machine Template</strong></summary>

- **Purpose**: User-controlled object can request machine certs and impersonate computers.  
- **Functionality**: Computer templates allow enrollment by authenticated users.  
- **Why It's Vulnerable**: Enroll for machine auth certificate using ESC1/3 privilege.  
- **How to Test**: Authenticate as computer using forged certificate.  
- **Tools**: ForgeCert, Rubeus  
- **Stealth Tips**: Use computer accounts not in monitoring scope.  

</details>
<a name="esc6%3A-authenticated-users-can-enroll"></a>
<details>
  <summary><strong>38. ESC6: Authenticated Users Can Enroll</strong></summary>

- **Purpose**: Any authenticated user can enroll on the template and impersonate others.  
- **Functionality**: Lax permissions on published templates allow wide abuse.  
- **Why It's Vulnerable**: Enumerate with Certify and enroll using target identity.  
- **How to Test**: Use Rubeus or ForgeCert to request cert, then Kerberos login.  
- **Tools**: Certify, Rubeus  
- **Stealth Tips**: Limit cert usage time and clean certificate store.  

</details>
<a name="esc7%3A-vulnerable-unused-template"></a>
<details>
  <summary><strong>39. ESC7: Vulnerable Unused Template</strong></summary>

- **Purpose**: Templates published but unused can still be abused by attackers.  
- **Functionality**: Old or legacy templates with insecure settings left exposed.  
- **Why It's Vulnerable**: Find unused templates with weak settings and enroll.  
- **How to Test**: Use Certify to list and ForgeCert to request.  
- **Tools**: Certify, ForgeCert  
- **Stealth Tips**: Avoid highly visible templates; cleanup metadata if possible.  

</details>
<a name="dcsync-via-genericall--replication-rights"></a>
<details>
  <summary><strong>40. DCSync via GenericAll / Replication Rights</strong></summary>

- **Purpose**: Obtain password hashes by syncing AD like a domain controller.  
- **Functionality**: Accounts with replication rights can pull sensitive data from NTDS.dit.  
- **Why It's Vulnerable**: Identify users/groups with 'Replicate Directory Changes' and use DCSync.  
- **How to Test**: Perform DCSync with Mimikatz or Impacket.  
- **Tools**: Mimikatz, Impacket, PowerView  
- **Stealth Tips**: Avoid frequent use; remove permissions post-exploitation.  

</details>
<a name="abusing-genericwrite-on-user-object"></a>
<details>
  <summary><strong>41. Abusing GenericWrite on User Object</strong></summary>

- **Purpose**: Gain access by overwriting sensitive attributes like logonScript or UPN.  
- **Functionality**: GenericWrite allows modifying user attributes for lateral movement.  
- **Why It's Vulnerable**: Use PowerView to identify writable user objects.  
- **How to Test**: Modify logonScript or set new UPN, then trigger login.  
- **Tools**: PowerView, PowerShell  
- **Stealth Tips**: Revert changes after gaining access to avoid detection.  

</details>
<a name="overpass-the-hash-%28pass-the-key%29"></a>
<details>
  <summary><strong>42. Overpass-the-Hash (Pass-the-Key)</strong></summary>

- **Purpose**: Authenticate with NTLM hash without cracking it.  
- **Functionality**: Kerberos TGT can be requested using NTLM hash and RC4-HMAC.  
- **Why It's Vulnerable**: Obtain NTLM hash using Mimikatz, then request TGT with Rubeus.  
- **How to Test**: Request TGT and inject with Rubeus.  
- **Tools**: Mimikatz, Rubeus  
- **Stealth Tips**: Use for short sessions; rotate ticket periodically.  

</details>
<a name="rbcd-via-addallowedtoact-%28acl-abuse%29"></a>
<details>
  <summary><strong>43. RBCD via AddAllowedToAct (ACL Abuse)</strong></summary>

- **Purpose**: Configure RBCD to allow any system to impersonate another.  
- **Functionality**: Write access to 'msDS-AllowedToActOnBehalfOfOtherIdentity' enables lateral movement.  
- **Why It's Vulnerable**: Grant RBCD rights on a privileged system to a controlled computer account.  
- **How to Test**: Create new computer object and configure RBCD, then authenticate.  
- **Tools**: PowerView, Rubeus, Powermad  
- **Stealth Tips**: Clean up computer object and delegation settings.  

</details>
<a name="abusing-resource-based-constrained-delegation-%28no-pre-auth%29"></a>
<details>
  <summary><strong>44. Abusing Resource-Based Constrained Delegation (No Pre-auth)</strong></summary>

- **Purpose**: Combine with AS-REP Roasting for delegation abuse.  
- **Functionality**: RBCD can be abused when pre-auth is disabled on accounts.  
- **Why It's Vulnerable**: Use AS-REP hash and configure RBCD via AddAllowedToAct.  
- **How to Test**: Crack hash and use delegation to impersonate user.  
- **Tools**: Rubeus, Mimikatz, PowerView  
- **Stealth Tips**: Avoid DA accounts; target non-monitored users.  

</details>
<a name="dcshadow-attack"></a>
<details>
  <summary><strong>45. DCShadow Attack</strong></summary>

- **Purpose**: Injects rogue changes directly into AD by impersonating a domain controller.  
- **Functionality**: Requires special privileges to register as a DC and push directory changes.  
- **Why It's Vulnerable**: Register attacker as rogue DC and push malicious attributes (e.g., SIDHistory).  
- **How to Test**: Use Mimikatz to run `lsadump::dcshadow` after configuring the environment.  
- **Tools**: Mimikatz  
- **Stealth Tips**: Use only with stealthy admin access; unregister DC after use.  

</details>
<a name="golden-ticket-attack"></a>
<details>
  <summary><strong>46. Golden Ticket Attack</strong></summary>

- **Purpose**: Create Kerberos TGT offline and impersonate any user, including domain admins.  
- **Functionality**: Requires KRBTGT NTLM hash, usually obtained via DCSync.  
- **Why It's Vulnerable**: Extract KRBTGT hash and forge a TGT with arbitrary SID and user.  
- **How to Test**: Forge TGT with Mimikatz and inject into session.  
- **Tools**: Mimikatz  
- **Stealth Tips**: Avoid ticket lifetime >1 hour; clean injected tickets.  

</details>
<a name="skeleton-key-attack"></a>
<details>
  <summary><strong>47. Skeleton Key Attack</strong></summary>

- **Purpose**: Load a master password (skeleton key) into memory to allow access to all accounts.  
- **Functionality**: Bypass authentication by patching LSASS process in memory.  
- **Why It's Vulnerable**: Inject skeleton key on DC using Mimikatz and use fixed password to log in.  
- **How to Test**: Run `mimikatz sekurlsa::patch` on DC and use key to authenticate.  
- **Tools**: Mimikatz  
- **Stealth Tips**: Trigger alerts on AV/EDR; limit use to labs or stealth environments.  

</details>
<a name="sidhistory-injection"></a>
<details>
  <summary><strong>48. SIDHistory Injection</strong></summary>

- **Purpose**: Grants elevated access by injecting SIDHistory from privileged accounts.  
- **Functionality**: Accounts with WriteMember rights can push privileged SIDs to low-priv accounts.  
- **Why It's Vulnerable**: Inject SIDHistory using Mimikatz or PowerShell on a domain-joined system.  
- **How to Test**: Modify LDAP attributes or use DCShadow to insert SIDs.  
- **Tools**: Mimikatz, PowerShell, DCShadow  
- **Stealth Tips**: Clean up SIDHistory to avoid detection and correlation.  

</details>
<a name="adminsdholder-abuse"></a>
<details>
  <summary><strong>49. AdminSDHolder Abuse</strong></summary>

- **Purpose**: Privilege persistence by modifying ACLs of protected accounts group template.  
- **Functionality**: Objects under AdminSDHolder inherit permissions every 60 minutes.  
- **Why It's Vulnerable**: Add backdoor ACEs to AdminSDHolder to persist access to DA accounts.  
- **How to Test**: Use PowerView to add rights and wait for SDProp job to apply ACLs.  
- **Tools**: PowerView, ADSI Edit  
- **Stealth Tips**: Remove ACEs from AdminSDHolder after use.  

</details>
<a name="unconstrained-delegation-abuse"></a>
<details>
  <summary><strong>50. Unconstrained Delegation Abuse</strong></summary>

- **Purpose**: Extract TGTs from memory of machines with unconstrained delegation.  
- **Functionality**: Any user logging onto these machines exposes their TGT in memory.  
- **Why It's Vulnerable**: Identify machines with unconstrained delegation using PowerView.  
- **How to Test**: Force authentication of DA to the host and dump memory.  
- **Tools**: PowerView, Rubeus, Mimikatz  
- **Stealth Tips**: Avoid triggering login manually; wait for natural authentication.  

</details>
<a name="kerberoasting-with-aes-keys"></a>
<details>
  <summary><strong>51. Kerberoasting with AES Keys</strong></summary>

- **Purpose**: Obtain TGS encrypted with AES256 for offline cracking.  
- **Functionality**: Modern environments use AES instead of RC4, requiring different cracking techniques.  
- **Why It's Vulnerable**: Use Rubeus to request TGS with /aes flag and crack offline.  
- **How to Test**: Target service accounts with SPNs and high privileges.  
- **Tools**: Rubeus, hashcat, john  
- **Stealth Tips**: Use selective SPN targeting to avoid noise.  

</details>
<a name="printer-bug-%2B-rbcd"></a>
<details>
  <summary><strong>52. Printer Bug + RBCD</strong></summary>

- **Purpose**: Use printer bug to coerce authentication, then relay to abuse RBCD.  
- **Functionality**: Triggers an SMB authentication from target system to relay point.  
- **Why It's Vulnerable**: Trigger bug using SpoolSample and relay via ntlmrelayx to configure RBCD.  
- **How to Test**: Exploit chain for lateral movement without direct DA rights.  
- **Tools**: SpoolSample, ntlmrelayx, impacket  
- **Stealth Tips**: Clean up delegation attributes post-access.  

</details>
<a name="kerberos-sid-filtering-bypass"></a>
<details>
  <summary><strong>53. Kerberos SID Filtering Bypass</strong></summary>

- **Purpose**: Exploit SID history to escalate across trusted domains.  
- **Functionality**: SID Filtering is bypassed in certain trust configurations.  
- **Why It's Vulnerable**: Add high-priv SID to SIDHistory in child domain user account.  
- **How to Test**: Authenticate as user and inherit elevated rights in parent domain.  
- **Tools**: Mimikatz, DCShadow, PowerShell  
- **Stealth Tips**: Requires external trust config understanding and careful SID injection.  

</details>
<a name="as-rep-roasting-%28aes-variant%29"></a>
<details>
  <summary><strong>54. AS-REP Roasting (AES Variant)</strong></summary>

- **Purpose**: Request encrypted AS-REP responses for users without pre-auth using AES.  
- **Functionality**: Stronger encryption requires updated tools and cracking techniques.  
- **Why It's Vulnerable**: Use Rubeus or GetNPUsers.py with AES output flag.  
- **How to Test**: Crack using hashcat with mode 18200.  
- **Tools**: Rubeus, Impacket, hashcat  
- **Stealth Tips**: Avoid brute-forcing strong passwords; target weak naming conventions.  

</details>
<a name="dnsadmin-to-dc-compromise"></a>
<details>
  <summary><strong>55. DNSAdmin to DC Compromise</strong></summary>

- **Purpose**: Use DNSAdmin rights to execute commands as SYSTEM on DC running DNS service.  
- **Functionality**: DNSAdmin has permission to modify service DLL path used by DNS server.  
- **Why It's Vulnerable**: Identify users/groups with DNSAdmin rights and inject malicious DLL.  
- **How to Test**: Restart DNS service or wait for reboot to trigger DLL execution.  
- **Tools**: PowerView, dnscmd, sc.exe  
- **Stealth Tips**: Limit visibility by restoring original DLL path quickly post-access.  

</details>
<a name="abusing-acl-on-gpo"></a>
<details>
  <summary><strong>56. Abusing ACL on GPO</strong></summary>

- **Purpose**: Modify Group Policy Object to execute payload on linked systems.  
- **Functionality**: Write rights on GPO lets attacker change scripts or registry settings.  
- **Why It's Vulnerable**: Identify GPOs linked to OUs with high-priv systems using SharpGPOAbuse.  
- **How to Test**: Inject startup script or Scheduled Task via GPO.  
- **Tools**: SharpGPOAbuse, gpmc.msc  
- **Stealth Tips**: Use fake GPO name or cleanup entries to avoid detection.  

</details>
<a name="shadow-credentials-%28key-credential-link-attack%29"></a>
<details>
  <summary><strong>57. Shadow Credentials (Key Credential Link Attack)</strong></summary>

- **Purpose**: Forge key credentials to authenticate as high-priv user.  
- **Functionality**: Attacker sets alternate credentials (certificate) if write access to user object.  
- **Why It's Vulnerable**: Add KeyCredential to user object and perform certificate authentication.  
- **How to Test**: Use Whisker or targeted scripts to register certificate.  
- **Tools**: Whisker, Certify, Rubeus  
- **Stealth Tips**: Requires cleanup of certificate mapping from user object.  

</details>
<a name="exchange-privesc-via-writedacl"></a>
<details>
  <summary><strong>58. Exchange PrivEsc via WriteDacl</strong></summary>

- **Purpose**: Abuse Exchange permissions to escalate to domain admin.  
- **Functionality**: Exchange groups often have excessive rights in domain.  
- **Why It's Vulnerable**: Identify Exchange Trusted Subsystem and grant DCSync rights to user.  
- **How to Test**: Perform DCSync after granting Replication rights.  
- **Tools**: PowerView, Mimikatz  
- **Stealth Tips**: Ensure Exchange permissions are restored after access.  

</details>
<a name="readgmsapassword-for-privilege-escalation"></a>
<details>
  <summary><strong>59. ReadGMSAPassword for Privilege Escalation</strong></summary>

- **Purpose**: Read Group Managed Service Account (gMSA) password hash.  
- **Functionality**: Users with read access to gMSA passwords can impersonate services.  
- **Why It's Vulnerable**: Query gMSA password using PowerShell or Mimikatz.  
- **How to Test**: Use hash for Overpass-the-Hash or service impersonation.  
- **Tools**: Mimikatz, PowerShell, Get-ADServiceAccount  
- **Stealth Tips**: Limit access to gMSAs and rotate credentials regularly.  

</details>
<a name="kerberos-delegation-loop"></a>
<details>
  <summary><strong>60. Kerberos Delegation Loop</strong></summary>

- **Purpose**: Create circular delegation paths to escalate privileges silently.  
- **Functionality**: Poorly configured delegation allows infinite loops via chained access.  
- **Why It's Vulnerable**: Analyze delegation paths using BloodHound or AD Explorer.  
- **How to Test**: Exploit loop to impersonate privileged accounts through chained delegation.  
- **Tools**: BloodHound, Rubeus, PowerView  
- **Stealth Tips**: Avoid noisy paths and clean misconfigured delegation entries.  

</details>
<a name="abuse-service-principal-name-%28spn%29-via-resource-based-constrained-delegation"></a>
<details>
  <summary><strong>61. Abuse Service Principal Name (SPN) via Resource-based Constrained Delegation</strong></summary>

- **Purpose**: Target SPN-registered objects to gain RBCD over a service.  
- **Functionality**: Improper ACLs on service objects allow attacker-controlled computer to configure delegation.  
- **Why It's Vulnerable**: Create a computer object and configure msDS-AllowedToActOnBehalfOfOtherIdentity.  
- **How to Test**: Use S4U2self + S4U2proxy to impersonate user to target service.  
- **Tools**: Rubeus, PowerView, SetSPN  
- **Stealth Tips**: Clean up computer object and delegation attributes post-access.  

</details>
<a name="malicious-gpo-deployment"></a>
<details>
  <summary><strong>62. Malicious GPO Deployment</strong></summary>

- **Purpose**: Deploy a malicious GPO to linked OU to gain persistence or escalate.  
- **Functionality**: Write access to GPO or linked OU enables this abuse.  
- **Why It's Vulnerable**: Craft GPO with startup script, task scheduler or backdoor setting.  
- **How to Test**: Link GPO to target OU using ADSI or GPMC tools.  
- **Tools**: SharpGPOAbuse, gpmc.msc, ADSI  
- **Stealth Tips**: Remove GPO or restore original policy post-operation.  

</details>
<a name="kerberos-constrained-delegation-%28kcd%29-abuse"></a>
<details>
  <summary><strong>63. Kerberos Constrained Delegation (KCD) Abuse</strong></summary>

- **Purpose**: Impersonate users to services using S4U2self and S4U2proxy with KCD.  
- **Functionality**: Requires delegation rights on target service account.  
- **Why It's Vulnerable**: Configure computer or user with msDS-AllowedToDelegateTo to impersonate.  
- **How to Test**: Use forged ticket to access service on behalf of privileged user.  
- **Tools**: Rubeus, PowerView  
- **Stealth Tips**: Target services with sensitive permissions only; clear logs.  

</details>
<a name="unquoted-service-path-privilege-escalation"></a>
<details>
  <summary><strong>64. Unquoted Service Path Privilege Escalation</strong></summary>

- **Purpose**: Exploit unquoted service path to execute malicious binary as SYSTEM.  
- **Functionality**: Service with unquoted path and spaces can lead to execution of attacker binary.  
- **Why It's Vulnerable**: Find services with unquoted paths using PowerUp.  
- **How to Test**: Place malicious executable in writable path portion.  
- **Tools**: PowerUp, sc.exe, accesschk.exe  
- **Stealth Tips**: Requires service restart; cleanup dropped files post-escalation.  

</details>
