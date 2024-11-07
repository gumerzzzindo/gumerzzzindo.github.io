---
layout: post
title: "Mi Write-up de Docker Labs"
categories: [htb]
tags: [pwn, buffer-overflow]
date: 2024-11-07
---
# Maquina domain dockerlabs

## Se nos presenta un escenario en el cual una maquina de docker con los siguientes servicios:

Nmap scan report for 172.17.0.2 (172.17.0.2)
PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.52 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2

1. Viendo que está el puerto 445 abierto vamos a ver los recursos:
```bash
smbclient -L 172.17.0.2 -N                                       
```
	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	html            Disk      HTML Share
	IPC$            IPC       IPC Service (db490d38775f server (Samba, Ubuntu))

### Cuando nos dirigimos a la web vemos una página mencionando lo que es samba, por lo que podemos ir deduciendo el vector de ataque.
    
2. Ahora que ya vemos los recursos podemos usar `rpcclient` para extraer usuarios:	
```bash
rpcclient -U '' -N 172.17.0.2
rpcclient $> qu
queryaliasinfo        querydispinfo         querydispinfo3        querygroup            querymultiplevalues   querysecret           queryuseraliases      quit
queryaliasmem         querydispinfo2        querydominfo          querygroupmem         querymultiplevalues2  queryuser             queryusergroups       
rpcclient $> querydis
querydispinfo   querydispinfo2  querydispinfo3  
rpcclient $> querydisfo
command not found: querydisfo
rpcclient $> querydisp
querydispinfo   querydispinfo2  querydispinfo3  
rpcclient $> querydispinfo
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: james	Name: james	Desc: 
index: 0x2 RID: 0x3e9 acb: 0x00000010 Account: bob	Name: bob	Desc: 
rpcclient $> enumdomusers
user:[james] rid:[0x3e8]
user:[bob] rid:[0x3e9]
```

Con `enumdomusers` se ve más claro.

3. Ahora, teniendo los usuarios enumerados, podemos hacer un spray de passwords.

4. Una vez tenemos la contraseña del usuario, vuelvo a usar `smbmap` y veo que hay un recurso con permisos de lectura y escritura llamado html.

Para conectar con el recurso html uso `smbclient`:
```bash
smbclient //172.17.0.2/html -U bob%star
```
## Tratamiento de TTY

### Mi método
```bash
script -c bash 2>/dev/null
Control + z 
stty raw echo; fg
reset xterm
export SHELL=bash
export TERM=xterm
```

### Método recomendable
```bash
script /dev/null -c bash
Control+Z
stty raw -echo; fg
reset
xterm
export SHELL=bash; export TERM=xterm
```
#### Así valdría pero si tienes que usar nano por ejemplo tienes que ajustar el tamaño de stty de tu term con la de shell
```bash
stty -a
```
