---
icon: globe-wifi
---

# Web Enumeration

## Web <a href="#http-https" id="http-https"></a>

### Fingerprinting <a href="#http-https" id="http-https"></a>

<pre class="language-bash"><code class="lang-bash"># Look at page with just text
curl 10.11.1.111 -s -L | html2text -width '99' | uniq

# Get everything
curl -i -L 10.11.1.111
curl -i -H "User-Agent:Mozilla/4.0" http://10.11.1.111:8080

<strong># Port 443
</strong>openssl s_client -connect &#x3C;hostname>:443

# Port 80
telnet &#x3C;IP> 80
</code></pre>

### Nikto - WebApp Scanning <a href="#http-https" id="http-https"></a>

```
nikto -h http://<url>
nikto -h $ip -p 80,8080,1234
```

### Gobuster - Directory Enumeration <a href="#gobuster" id="gobuster"></a>

```
gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -u http://192.168.3.104 -x php,txt,bak
```

_**Some extension**_

```bash
sh,txt,php,html,htm,asp,aspx,js,xml,log,json,jpg,jpeg,png,gif,doc,pdf,mpg,mp3,zip,tar.gz,tar
```

### ffuf -  Fuzzing Parameters <a href="#ffuf" id="ffuf"></a>

```

ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c --recursion    

```

### wpscan - wordpress scan

```bash
wpscan --update
wpscan --url <ip>
wpscan --url [url] --enumerate [p/vp/ap/t/vt/at] --plugins-detection aggressive

# To scan for all plugins
wpscan --url [url] --enumerate ap --plugins-detection aggressive

# Enumerating wordpress users
wpscan --url [target URL] --enumerate u

# Password Attack
wpscan --url http://internal.thm/blog/ --passwords /opt/wordlists/rockyou.txt
```

### Uniscan <a href="#uniscan" id="uniscan"></a>

LFI, RFI, and RCE vulnerability scanner

```
uniscan -u http://192.168.1.202/ -qd
```

### CMS Explorer

```

cms-explorer -url http://10.11.1.111 -type [Drupal, WordPress, Joomla, Mambo]
```



## :heartbeat:Resources

Amazing compilation -> [https://pentestbook.six2dez.com/enumeration/web](https://pentestbook.six2dez.com/enumeration/web)



