---
icon: linux
---

# ClamAV

## Summary

* Target exposed SNMP, SMTP, Apache, Samba, and ClamAV-related services.&#x20;
* SNMP enumeration revealed valuable system/process details, including an exposed `clamav-milter` service.&#x20;
* The misconfiguration in the ClamAV milter process was later exploited to gain a root shell directly.

## 🧵 Let's Unpack

#### 🚪 Enumeration

#### 🔍 Nmap Full TCP Scan

```
nmap -p- -T5 192.168.167.42 -vv
```

#### 🔎 Detailed Nmap Service Scan

```
sudo nmap -sC -sN -A -oN nmapFull -p- 22,25,80,139,199,445,60000 -A 192.168.167.42
```

**Key Findings:**

* Open services: SSH, SMTP, HTTP , SMB, SNMP
* High port `60000` open

***

### SMTP Enumeration (Port 25)

```
nc -vv 192.168.167.42 25
```

* Found running: `Sendmail 8.13.4/Debian-3sarge3`
* No misconfig or banner leaks observed

***

### SNMP Enumeration (Port 161)

```
snmp-check 192.168.167.42
```

<details>

<summary>Detailed SNMP findings</summary>

```shell
[*] System information:

  Host IP address               : 192.168.167.42
  Hostname                      : 0xbabe.local
  Description                   : Linux 0xbabe.local 2.6.8-4-386 #1 Wed Feb 20 06:15:54 UTC 2008 i686
  Contact                       : Root <root@localhost> (configure /etc/snmp/snmpd.local.conf)
  Location                      : Unknown (configure /etc/snmp/snmpd.local.conf)
  Uptime snmp                   : 01:01:25.95
  Uptime system                 : 01:00:47.84
  System date                   : 2024-7-27 08:57:31.0

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 64
  TCP segments received         : 147308
  TCP segments sent             : 147229
  TCP segments retrans          : 0
  Input datagrams               : 147422
  Delivered datagrams           : 147422
  Output datagrams              : 147313

[*] Network interfaces:

  Interface                     : [ up ] lo
  Id                            : 1
  Mac Address                   : :::::
  Type                          : softwareLoopback
  Speed                         : 10 Mbps
  MTU                           : 16436
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ up ] eth0
  Id                            : 2
  Mac Address                   : 00:50:56:ab:8e:d4
  Type                          : ethernet-csmacd
  Speed                         : 100 Mbps
  MTU                           : 1500
  In octets                     : 11538726
  Out octets                    : 8859062

  Interface                     : [ down ] sit0
  Id                            : 3
  Mac Address                   : 00:00:00:00:8e:d4
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 1480
  In octets                     : 0
  Out octets                    : 0


[*] Network IP:

  Id                    IP Address            Netmask               Broadcast           
  1                     127.0.0.1             255.0.0.0             0                   
  2                     192.168.167.42        255.255.255.0         1                   

[*] Routing information:

  Destination           Next hop              Mask                  Metric              
  0.0.0.0               192.168.167.254       0.0.0.0               1                   
  192.168.167.0         0.0.0.0               255.255.255.0         0                   

[*] TCP connections and listening ports:

  Local address         Local port            Remote address        Remote port           State               
  0.0.0.0               25                    0.0.0.0               0                     listen              
  0.0.0.0               80                    0.0.0.0               0                     listen              
  0.0.0.0               139                   0.0.0.0               0                     listen              
  0.0.0.0               199                   0.0.0.0               0                     listen              
  0.0.0.0               445                   0.0.0.0               0                     listen              

[*] Listening UDP ports:

  Local address         Local port          
  0.0.0.0               137                 
  0.0.0.0               138                 
  0.0.0.0               161                 
  192.168.167.42        137                 
  192.168.167.42        138                 

[*] Processes:

  Id                    Status                Name                  Path                  Parameters          
  1                     runnable              init                  init [2]                                  
  2                     runnable              ksoftirqd/0           ksoftirqd/0                               
  3                     runnable              events/0              events/0                                  
  4                     runnable              khelper               khelper                                   
  5                     runnable              kacpid                kacpid                                    
  99                    runnable              kblockd/0             kblockd/0                                 
  109                   runnable              pdflush               pdflush                                   
  110                   runnable              pdflush               pdflush                                   
  111                   runnable              kswapd0               kswapd0                                   
  112                   runnable              aio/0                 aio/0                                     
  255                   runnable              kseriod               kseriod                                   
  276                   runnable              scsi_eh_0             scsi_eh_0                                 
  284                   runnable              khubd                 khubd                                     
  348                   runnable              shpchpd_event         shpchpd_event                             
  380                   runnable              kjournald             kjournald                                 
  935                   runnable              vmmemctl              vmmemctl                                  
  1177                  runnable              vmtoolsd              /usr/sbin/vmtoolsd                        
  3770                  running               syslogd               /sbin/syslogd                             
  3773                  runnable              klogd                 /sbin/klogd                               
  3777                  runnable              clamd                 /usr/local/sbin/clamd                      
  3779                  runnable              clamav-milter         /usr/local/sbin/clamav-milter  --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
  3788                  runnable              inetd                 /usr/sbin/inetd                           
  3792                  runnable              nmbd                  /usr/sbin/nmbd        -D                  
  3794                  runnable              smbd                  /usr/sbin/smbd        -D                  
  3798                  running               snmpd                 /usr/sbin/snmpd       -Lsd -Lf /dev/null -p /var/run/snmpd.pid
  3800                  runnable              smbd                  /usr/sbin/smbd        -D                  
  3805                  runnable              sshd                  /usr/sbin/sshd                            
  3883                  runnable              sendmail-mta          sendmail: MTA: accepting connections                      
  3900                  runnable              atd                   /usr/sbin/atd                             
  3903                  runnable              cron                  /usr/sbin/cron                            
  3910                  runnable              apache                /usr/sbin/apache                          
  3926                  runnable              getty                 /sbin/getty           38400 tty1          
  3932                  runnable              getty                 /sbin/getty           38400 tty2          
  3933                  runnable              getty                 /sbin/getty           38400 tty3          
  3934                  runnable              getty                 /sbin/getty           38400 tty4          
  3935                  runnable              getty                 /sbin/getty           38400 tty5          
  3936                  runnable              getty                 /sbin/getty           38400 tty6          
  3971                  runnable              apache                /usr/sbin/apache                          
  3972                  runnable              apache                /usr/sbin/apache                          
  3973                  runnable              apache                /usr/sbin/apache                          
  3974                  runnable              apache                /usr/sbin/apache                          
  3975                  runnable              apache                /usr/sbin/apache                          
  4048                  runnable              apache                /usr/sbin/apache                          

[*] Storage information:

  Description                   : ["Real Memory"]
  Device id                     : [#<SNMP::Integer:0x0000ffff8e4e0b18 @value=2>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x0000ffff8e4def48 @value=1024>]
  Memory size                   : 250.82 MB
  Memory used                   : 117.00 MB

  Description                   : ["Swap Space"]
  Device id                     : [#<SNMP::Integer:0x0000ffff8e4da010 @value=3>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x0000ffff8e4d8468 @value=1024>]
  Memory size                   : 203.91 MB
  Memory used                   : 0 bytes

  Description                   : ["/"]
  Device id                     : [#<SNMP::Integer:0x0000ffff8e4d36e8 @value=4>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x0000ffff8e4d1b40 @value=4096>]
  Memory size                   : 3.74 GB
  Memory used                   : 765.65 MB

  Description                   : ["/sys"]
  Device id                     : [#<SNMP::Integer:0x0000ffff8e4ccd98 @value=5>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x0000ffff8e4cb1c8 @value=4096>]
  Memory size                   : 0 bytes
  Memory used                   : 0 bytes


[*] File system information:

  Index                         : 1
  Mount point                   : /
  Remote mount point            : -
  Access                        : 1
  Bootable                      : 1

[*] Device information:

  Id                    Type                  Status                Descr               
  768                   unknown               unknown               AuthenticAMD: AMD EPYC 7413 24-Core Processor
  1025                  unknown               running               network interface lo
  1026                  unknown               running               network interface eth0
  1027                  unknown               down                  network interface sit0
  1536                  unknown               unknown               VMware Virtual IDE CDROM Drive
  1552                  unknown               unknown               SCSI disk (/dev/sda)
  3072                  unknown               unknown               Guessing that there's a floating point co-processor

```

</details>

**Key Findings:**

* Hostname: `0xbabe.local`
* OS: Linux kernel 2.6.8 (outdated)
* Running process: `clamav-milter` observed with full path: `/usr/local/sbin/clamav-milter`
* Listening TCP Ports: 25 (SMTP), 80 (HTTP), 139/445 (SMB), 199, 60000
* UID 3779 shows `clamav-milter` with parameters hinting socket usage

> 💡 `clamav-milter` running and exposed is a strong indicator to search for local exploits.

***

### Initial Foothold (Root Directly)

Found local exploit for `clamav-milter` vulnerability:

📌 **Exploit**: https://www.exploit-db.com/exploits/4761

#### 🎯 Exploitation Steps

1. Compile and run the exploit locally or transfer it via HTTP/SMB.
2. Exploit opens a reverse shell listener on the target's port 31337.

```
nc -nv 192.168.167.42 31337
```

3. Got direct `root` shell 🎉

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

***

### 🧠 Gotcha!

> The `clamav-milter` process running with elevated privileges and exposed via SNMP was the hidden gem. Always inspect process listings in SNMP responses — they can leak exploitable services.

***

### Privilege Escalation

Not needed — root shell gained directly via local misconfiguration exploit.

***

###
