---
layout: single
title: "LSASS Credential Dumping: técnicas, OPSEC y detección"
date: 2026-06-28
categories: [tutoriales, malware]
tags: [windows, credentials, lsass, mimikatz, nanodump, evasion, offensive]
excerpt: "Volcado de credenciales desde LSASS en Windows: técnicas clásicas, alternativas LOLBAS, variantes evasivas y cómo los defensores lo detectan."
permalink: /tutoriales/lsass-credential-dumping/
---

LSASS (*Local Security Authority Subsystem Service*) es el proceso que valida inicios de sesión en Windows. Como efecto secundario de ese trabajo, mantiene en memoria credenciales en distintos formatos — hashes NT, tickets Kerberos, credenciales en claro bajo determinadas configuraciones. Eso lo convierte en el objetivo de credential access por excelencia.

Este post cubre las técnicas más habituales de volcado, sus requisitos, las defensas que las bloquean y qué telemetría generan.

## Credenciales en LSASS

Antes de volcar nada, conviene entender qué hay ahí dentro:

| Tipo | Condición |
|---|---|
| Hash NT (NTLM) | Siempre presente en dominio/local |
| Ticket Kerberos TGT | Sesiones de dominio |
| Hash NTLMv2 challenge/response | En caché durante autenticación |
| Credenciales en claro (WDigest) | Windows ≤ 8.1 / WDigest habilitado |
| Credenciales DPAPI | Claves maestras de sesión |

WDigest está deshabilitado por defecto desde Windows 8.1 / Server 2012 R2. El registro relevante:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
UseLogonCredential = 0  (default, no cleartext)
```

Un atacante con permisos de escritura en ese registro puede activarlo y esperar a que la víctima vuelva a autenticarse.

## Técnicas de volcado

### 1. Mimikatz — sekurlsa::logonpasswords

La referencia. Requiere `SeDebugPrivilege` (habitualmente disponible para administradores locales).

```
privilege::debug
sekurlsa::logonpasswords
```

Extrae todos los proveedores SSP cargados en LSASS. El output incluye hashes NT, dominio, usuario y — si WDigest está activo — password en claro.

Para Pass-the-Hash directamente:

```
sekurlsa::pth /user:administrador /domain:corp.local /ntlm:<HASH> /run:cmd.exe
```

### 2. comsvcs.dll MiniDump (LOLBAS)

`comsvcs.dll` exporta la función `MiniDump`, invocable via `rundll32` sin binarios adicionales. Solo necesitas el PID de `lsass.exe`.

```powershell
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\Windows\Temp\lsass.dmp full
```

El fichero resultante se puede analizar offline con Mimikatz:

```
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

Esta técnica es eficaz porque usa un binario firmado por Microsoft. El `MiniDump` llama a `MiniDumpWriteDump` internamente, lo que genera el mismo handle a LSASS con `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`.

### 3. ProcDump (SysInternals)

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Firmado por Microsoft, a menudo whitelisted por defensas legacy. Genera un `MiniDumpWithFullMemory`. Algunos EDR lo marcan específicamente cuando el proceso destino es `lsass.exe`.

### 4. Task Manager

Via GUI: Task Manager → Details → click derecho sobre `lsass.exe` → *Create dump file*. Escribe el dump en `%TEMP%\lsass.DMP`. Poco útil en red pero hay que conocerlo.

### 5. Nanodump — volcado evasivo

[Nanodump](https://github.com/helpsystems/nanodump) de HelpSystems es un reflective loader que utiliza syscalls directas para evitar hooks en userland. En lugar de llamar a `MiniDumpWriteDump`, implementa el parsing del formato minidump manualmente y escribe el fichero con `NtWriteFile`.

Características principales:
- Usa `NtReadVirtualMemory` directamente (sin pasar por `ntdll` hookeada)
- Soporta volcado en un handle cifrado para no escribir el dump en disco en claro
- Compatible con secuencias de `fork + dump` para evitar abrir handle directo a `lsass.exe`

```bash
# Compilar y usar
nanodump.x64.exe --write C:\Windows\Temp\nc.dmp --fork
```

La técnica `--fork` crea un proceso hijo clonado de LSASS mediante `NtCreateProcessEx` con `ProcessFlags = PROCESS_CREATE_FLAGS_INHERIT_HANDLES`. El handle abierto es al proceso clonado, no al LSASS real — dificulta detecciones que correlacionan accesos directos a `lsass.exe`.

### 6. Dumpert — handle directo con syscalls

[Dumpert](https://github.com/outflanknl/Dumpert) de Outflank abre un handle a LSASS evitando las APIs de Win32 hookeadas:

```c
// Fragmento conceptual — abre handle via NtOpenProcess directo
OBJECT_ATTRIBUTES oa = { sizeof(oa) };
CLIENT_ID cid = { (HANDLE)lsass_pid, 0 };
NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
```

El mismo enfoque que Hell's Gate / Halos Gate aplicado a credential dumping. Si el EDR hookea solo en `ntdll.dll` a nivel de `OpenProcess`, el acceso directo a la syscall lo evade.

## PPL — Protected Process Light

A partir de Windows 8.1, LSASS puede correr como Protected Process Light (`PsProtectedSignerLsa-Light`). En ese modo, solo procesos con nivel de protección igual o superior pueden abrir un handle con acceso a su memoria.

```powershell
# Verificar si PPL está activo
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL
```

Valor `1` = PPL activo. Con PPL habilitado, técnicas de userland que abren handle a LSASS fallan con `Access is denied`.

Para bypasear PPL se necesita código en kernel mode. El módulo `mimidrv.sys` de Mimikatz hace exactamente eso — carga un driver que modifica la estructura `EPROCESS` del proceso LSASS para eliminar su protección:

```
!+
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
```

Requiere `SeLoadDriverPrivilege` y que SecureBoot + DSE no bloqueen el driver sin firma válida. Con Kernel Mode Code Signing (KMCS) activo, necesitas un driver firmado o una vulnerabilidad de driver conocida para cargarlo (BYOVD).

## Credential Guard

Credential Guard aísla las credenciales en un proceso separado (`lsasiso.exe`) ejecutándose en VTL1 (Virtualization-Based Security). Hashes NT y tickets Kerberos se almacenan ahí y solo están disponibles a través de RPC desde VTL0.

Volcar LSASS con Credential Guard activo da hashes inutilizables — solo devuelve el stub de VTL0, no el secreto real.

```powershell
# Estado de Credential Guard
(Get-ComputerInfo).DeviceGuardCredentialGuardRunning
```

No existe bypass desde userland. Requiere comprometer VTL1 o deshabilitar VBS a nivel de firmware/hypervisor.

## Detecciones

### Event IDs relevantes

| Event ID | Canal | Descripción |
|---|---|---|
| 4656 | Security | Handle request sobre un objeto (lsass.exe) |
| 4663 | Security | Acceso a objeto con `ReadProcessMemory` |
| 10 | Sysmon | `ProcessAccess` — fuente, destino, derechos de acceso |
| 7 | Sysmon | `ImageLoad` — cargas de `comsvcs.dll` inusuales |

El Sysmon Event ID 10 es el más usado en reglas YARA/Sigma para detectar dumping. Un ejemplo de regla Sigma:

```yaml
title: LSASS Memory Dump via ProcessAccess
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1038'
      - '0x143a'
  condition: selection
```

Los valores de `GrantedAccess` corresponden a combinaciones de `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` que son necesarios para leer la memoria de LSASS.

### ETW — Microsoft-Windows-Kernel-Process

El proveedor ETW `Microsoft-Windows-Threat-Intelligence` (TELEMETRY) en kernel space registra `ReadProcessMemory` incluso cuando se usan syscalls directas. EDR modernos (CrowdStrike Falcon, Microsoft Defender for Endpoint) lo consumen y correlacionan independientemente de los hooks de userland.

Para bypassear esto se requiere deshabilitar o filtrar el proveedor ETW a nivel de kernel — lo que entra en territorio de manipulación de kernel (BYOVD, kernel exploit) y aumenta considerablemente el nivel de complejidad y detección.

## OPSEC mínimo

Si se hace credential dumping en un engagement:
- Evitar escribir el dump en disco en claro — cifrar en memoria antes de exfiltrar
- Preferir fork + dump en lugar de handle directo a `lsass.exe`
- No usar ProcDump ni Task Manager en entornos monitorizados — generan IoCs triviales
- En entornos con Credential Guard, pivotal hacia técnicas alternativas: Shadow Credentials, Kerberoasting, DCSync via replicación

## Referencias

- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Nanodump — HelpSystems](https://github.com/helpsystems/nanodump)
- [Dumpert — Outflank](https://github.com/outflanknl/Dumpert)
- [LSASS Protection — Microsoft Docs](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Sigma rule: LSASS ProcessAccess](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml)
- [VBS / Credential Guard architecture](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
