---
description: Auto-parsed spreadsheets on the mail server + LibreOffice macros injection
icon: windows
---

# Hepet

## Summary

* Discovered a wide attack surface: mail services, multiple HTTP ports, FTP, VNC, and Microsoft RPC endpoints.
* Anonymous FTP access revealed internal files but no write permission.
* Web app on port 443 listed employee names, useful for username generation.
* Finger service on port 79 helped enumerate valid usernames.
* IMAP login (via Evolution client) revealed internal emails:
  * Organization uses **LibreOffice** for documents.
  * Employees are asked to send spreadsheets to `mailadmin@localhost`, where they are “automatically processed.”
*

***

### 🧵 Let's Unpack

## Enumeration

**🔹 Nmap Full TCP Scan**

```bash
nmap -p- -T5 192.168.172.140 -vv
# Extracted open ports:
25,79,105,106,110,135,139,143,443,445,2224,5040,8000,11100,20001,33006,49664-49669
```

**🔹 Nmap Detailed Service Scan**

```bash
sudo nmap -sC -sN -A -p [above ports] 192.168.172.140
```

* Multiple **Mercury/32** mail services (SMTP, POP3, IMAP, HTTP, Finger)
* Apache HTTP server on ports 443 & 8000 hosting a “Time Travel Company” site
* VNC on port `11100` with unknown auth type (40)
* FTP on `20001` allowed **anonymous login**
* IMAP on port `143` revealed accessible emails after login

***

#### 🗂️ FTP Enumeration – Port 20001

```bash
ftp 192.168.172.140 -p 20001
```

* Anonymous login allowed.
* Found frontend dev files: `.babelrc`, `index.html`, `README.md`, `src/`, etc.
* No upload rights available — marked for later revisit once credentials are obtained.

***

#### 🖥️ Web App Recon – Ports 443 / 8000

* Site lists employee names: _Agnes, Charlotte, Ela Arwel, Magnus, Jonas, Martha_
*   Guessed usernames:

    ```
    agnes, charlotte, jonas, magnus, martha, ela_arwel
    ```
* Captured for use across email, FTP, and finger enumeration.

***

#### ☎️ Finger Service – Port 79

* Used `finger-user-enum.pl` and `nc` to validate usernames.
* Discovered that `agnes`, `charlotte`, `jonas`, `magnus`, and `martha` are valid accounts.
*   Verified one set of credentials:

    ```
    jonas:SicMundusCreatusEst
    ```

***

#### 📩 IMAP Enumeration – Port 143

Used **Evolution Mail Client** to log in via IMAP and read messages.

**Key Findings from Emails:**

* Employees use **LibreOffice** for documents.
* Emails containing spreadsheets sent to `mailadmin@localhost` are auto-processed.
* Strong indicator of **automated document parsing pipeline** on the mail server.

***

Took help from official writeup after this.&#x20;

:bulb:Hint:

* After reading internal emails via IMAP, you’ll find that documents sent to `mailadmin@localhost` are auto-processed using LibreOffice.
* 🧠 Craft a `.ods` spreadsheet with a malicious **macro payload**, and email it to `mailadmin@localhost` to gain code execution.





## Privilege Escalation

:bulb:Hint:

* Once you gain a foothold, enumerate running services.&#x20;
* If you find any service binary residing inside the current user’s directory and running as `SYSTEM`, you may be able to **replace it with a reverse shell** and trigger it via system reboot for privilege escalation. :wink'

