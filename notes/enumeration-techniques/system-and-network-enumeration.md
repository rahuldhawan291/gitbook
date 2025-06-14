---
icon: linux
---

# System and Network Enumeration

## Nmap

<pre class="language-bash"><code class="lang-bash"><strong>sudo nmap -A -T4 -sV -sC -p- -Pn  $ip --open
</strong>
# for udp scan use following along with sudo
-sU

</code></pre>

_However, I found the following approach bit faster_

```bash
# Step 1: Quick port scan
nmap -p- -T5 $ip > ports

# Step 2: Grep and extract out the ports; the output would be like 22,25,80
cat ports | awk '{split($0,a,"/"); print a[1] ","}'| tr -d "\n"| awk 'BEGIN {FS=OFS=","} NF--'
>

# step 3 - Dive deeper into the ports found above
sudo nmap -A -T4 -sC -sN -oN nmapFull -p 22,25,80 $ip -Pn

```

## Auto-Recon

_Run this along with nmap._&#x20;

```bash
autorecon $ip
```

## enum4linux

_Run this along with nmap._&#x20;

```bash
enum4linux -u 'guest' -p '' $ip
```



## Massscan

```bash
masscan -e tun0 -p1-65535,U:1-65535 10.10.10.116
```
