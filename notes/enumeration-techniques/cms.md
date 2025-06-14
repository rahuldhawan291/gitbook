---
icon: wordpress
---

# CMS

## CMS Explorer

```

cms-explorer -url http://10.11.1.111 -type [Drupal, WordPress, Joomla, Mambo]
```

{% embed url="https://gabb4r.gitbook.io/oscp-notes/web-http/cms" %}

## **Wordpress**

```bash
###### Interesting path/pages
# admin login
/wp-admin
/wp-login

# Configuration files
setup-config.php
wp-config.php

# enumerate user
/?author=1, /?author=2,

```

### [ ](https://notes.offsec-journey.com/enumeration/ftp)Uploading shell in WP\_THEME

Amazing Article -> [https://www.hackingarticles.in/wordpress-reverse-shell/](https://www.hackingarticles.in/wordpress-reverse-shell/)

<pre class="language-bash"><code class="lang-bash"><strong>
</strong><strong># Scanning workpress for 
</strong><strong>wscan -e vp --plugins-detection aggressive --api-token &#x3C;API>--url &#x3C;URL> --disable-tls-checks   
</strong>
#User enum
wfuzz -c -u http://&#x3C;IP>/wp-login.php -z file,/opt/SecLists/Usernames/Names/names.txt -d "log=FUZZ&#x26;pwd=pass&#x26;wp-submit=Log+In&#x26;redirect_to=http%3A%2F%2Ffunbox.fritz.box%2Fwp-admin%2F&#x26;testcookie=1" --hw 308

# bruteforcing using hydra
hydra -L user.txt -P /usr/share/wordlists/rockyou.txt http://10.10.224.210/retro -V http-form-post '/wp-login.php:log=^USER^&#x26;pwd=^PASS^&#x26;wp-submit=Log In&#x26;testcookie=1:S=Location'
      
</code></pre>



## Drupal <a href="#drupal" id="drupal"></a>

More Details here -> [https://notes.offsec-journey.com/enumeration/content-management-systems](https://notes.offsec-journey.com/enumeration/content-management-systems)

```bash
#https://github.com/droope/droopescan
./droopescan scan drupal -u 10.10.10.13

#https://github.com/immunIT/drupwn
python3 drupwn <URL>
```



\
 <a href="#drupal" id="drupal"></a>
-----------------------------------
