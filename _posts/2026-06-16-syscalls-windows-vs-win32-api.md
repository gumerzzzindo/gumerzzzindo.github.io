---
layout: single
title: "Syscalls de Windows vs Win32 API: por qué nadie llama directamente al kernel"
date: 2026-06-16
categories: [tutoriales, malware]
tags: [windows-internals, syscalls, win32api, ntdll, ntoskrnl, seguridad-en-capas, edr, evasion]
excerpt: "Win32 API, ntdll.dll y syscalls nativas: qué hace cada capa, por qué el código normal nunca toca el kernel directamente, y cómo el malware moderno explota eso para evadir EDRs."
permalink: /tutoriales/syscalls-windows-vs-win32-api/
---

Cuando se escribe `CreateFileW()` en C, o `Process.Start()` en .NET, en realidad no se está hablando con el kernel. Se está hablando con una API de usuario que, varias capas más abajo, termina pidiéndole permiso al kernel para hacer el trabajo real. Entender esas capas explica por qué el malware moderno casi siempre intenta saltárselas, y por qué eso es exactamente lo que vigila un EDR.

## Las tres capas, de arriba a abajo

```text
[ Tu programa ]
       │  CreateFileW(), VirtualAlloc(), WriteProcessMemory()...
       ▼
[ Win32 API ]               kernel32.dll, advapi32.dll, user32.dll...
       │  valida parámetros, traduce a formato NT, gestiona compatibilidad
       ▼
[ Native API ]              ntdll.dll
       │  NtCreateFile(), NtAllocateVirtualMemory()...
       │  carga el SSN en RAX, copia RCX en R10, ejecuta syscall
       ▼
[ Syscall — transición a kernel ]
       │  cambio de anillo: Ring 3 (usuario) → Ring 0 (kernel)
       ▼
[ ntoskrnl.exe — el kernel ]
       │  comprueba permisos, accede al objeto real, ejecuta la operación
       ▼
[ Hardware / drivers ]
```

Tres capas, tres responsabilidades:

- **Win32 API** (`kernel32.dll`, `user32.dll`, `advapi32.dll`): la interfaz documentada y estable entre versiones de Windows. Valida parámetros, gestiona compatibilidad y traduce las llamadas al formato interno de Windows (NT).
- **Native API** (`ntdll.dll`): las funciones `Nt*` son los stubs que invocan al kernel. Preparan la llamada cargando el *System Service Number* (SSN) en `RAX` y copiando `RCX` en `R10`, porque la instrucción `syscall` sobreescribe `RCX` con la dirección de retorno. No están documentadas para uso en aplicaciones, aunque sus equivalentes kernel-mode (`Zw*`) sí lo están en el WDK.
- **Syscall**: en Windows x64 moderno, la instrucción `syscall` ejecuta el cambio de privilegio de Ring 3 a Ring 0. En sistemas legacy de 32 bits se usaba `int 0x2e` (Windows NT hasta 2000) y posteriormente `sysenter` (XP/Vista 32-bit) — mecanismos secuenciales, no equivalentes, que desaparecieron con la transición a x64.

El kernel identifica la operación solicitada por el SSN en `RAX`, un índice en la *System Service Descriptor Table* (SSDT) que apunta a la función del kernel correspondiente.

## Qué pasa exactamente cuando llamas a CreateFileW

Siguiendo el flujo con un ejemplo concreto:

1. Tu código llama a `CreateFileW()` en `kernel32.dll`.
2. `kernel32.dll` valida parámetros, convierte el path a formato NT (`\??\C:\ruta`), y llama a `NtCreateFile()` en `ntdll.dll`.
3. El stub de `NtCreateFile` en `ntdll.dll` hace algo así:

```nasm
; NtCreateFile stub en ntdll.dll (x64, Windows 10/11)
mov r10, rcx          ; syscall convention: primer argumento a r10
mov eax, 0x55         ; SSN de NtCreateFile (varía por versión de Windows)
syscall               ; transición a Ring 0
ret
```

4. La CPU entra en kernel mode. El *System Service Dispatcher* (`KiSystemCall64` en `ntoskrnl.exe`) recibe el SSN, busca la función en la SSDT y la ejecuta.
5. El kernel comprueba permisos, resuelve el objeto en el *Object Manager*, y hace el trabajo real.
6. El resultado vuelve a Ring 3 como `NTSTATUS`.

El SSN es simplemente un índice en una tabla — no hay nombre de función ni string de por medio.

## Por qué el código normal no usa syscalls directas

**Portabilidad.** El SSN de `NtCreateFile` en Windows 7 es distinto al de Windows 10 y al de Windows 11. Si hardcodeas el número, tu programa tendrá comportamiento inesperado en otra versión. `ntdll.dll` abstrae eso: los stubs siempre tienen el SSN correcto para la versión en ejecución.

**Estabilidad de API.** Microsoft garantiza que la Win32 API es estable. La Native API no está garantizada — pueden cambiar parámetros, comportamiento o SSNs en cualquier update. Programar contra `kernel32.dll` da compatibilidad hacia adelante; hacerlo contra SSNs hardcodeados, no.

## ¿Windows tiene seguridad por capas de verdad?

Sí, aunque no donde la mayoría espera.

El modelo de anillos de la CPU (Ring 0 / Ring 3) es la separación real y obligatoria. El kernel corre en Ring 0 con acceso total al hardware y la memoria. El código de usuario corre en Ring 3 y no puede acceder directamente a nada privilegiado — la CPU lo impide a nivel hardware. La única forma de cruzar esa frontera es a través de una syscall.

Las capas superiores (Win32 API → ntdll → syscall) son capas de *abstracción y compatibilidad*, no de seguridad. La seguridad real la impone el kernel al recibir la syscall:

- **Access Control**: ¿tiene el proceso el `HANDLE` con los permisos correctos?
- **Token/privilegios**: ¿tiene el proceso el privilegio requerido (p. ej. `SeDebugPrivilege`)?
- **Integrity Level**: ¿el nivel de integridad del proceso permite la operación?
- **Object Security Descriptor**: ¿la DACL del objeto permite al SID del proceso esa acción?

`kernel32.dll` hace validación básica de parámetros, pero la seguridad real vive en el kernel.

## Cómo lo aprovecha el malware

Un EDR moderno coloca *hooks* en las funciones `Nt*` de `ntdll.dll`: modifica los primeros bytes del stub para redirigir la ejecución a su propio código antes de que llegue al kernel. Si el malware lo sabe, puede saltárselo:

**Direct syscalls.** En lugar de llamar al stub hooked de ntdll, el malware implementa el suyo propio con el SSN correcto y ejecuta `syscall` directamente. El hook del EDR nunca se dispara. Herramientas como SysWhispers automatizan la generación de stubs por versión de Windows.

**Indirect syscalls.** Variante más evasiva: el malware salta directamente a la instrucción `syscall` *dentro* del stub legítimo de ntdll, eludiendo los bytes hooked al inicio. El `syscall` original se ejecuta, pero el call stack no apunta a ntdll — evitando también las detecciones basadas en stack de retorno.

**Hell's Gate / Halo's Gate.** Técnicas para obtener el SSN en tiempo de ejecución sin hardcodearlo. Hell's Gate lee el SSN desde los bytes del stub en memoria. Halo's Gate resuelve el caso en que el stub ya está hooked buscando stubs vecinos sin parchear y calculando el SSN por diferencia de índice.

**Unhooking.** Restaurar el código original de `ntdll.dll` en memoria — cargando una copia limpia desde disco, desde `KnownDlls`, o copiándola de la sección de la DLL en otro proceso. El hook desaparece físicamente.

## Qué vigila un EDR

Los EDRs modernos han añadido capas de detección independientes de los hooks en user-mode:

- **ETW (Event Tracing for Windows)**: el kernel emite eventos nativos para operaciones sensibles. El proveedor `Microsoft-Windows-Threat-Intelligence` da telemetría desde Ring 0 independientemente de si el malware usó direct syscalls.
- **Kernel callbacks**: `PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, minifilter drivers — el EDR registra callbacks en el kernel que se ejecutan ante eventos del sistema sin depender de los stubs de ntdll.
- **Análisis del call stack**: una syscall cuyo stack de retorno no pasa por ntdll es señal de direct syscall — algo que los EDRs modernos detectan activamente.

| Técnica del malware | Evita hook ntdll | Evita ETW kernel | Evita kernel callbacks |
|---|---|---|---|
| Llamada normal (Win32) | No | No | No |
| Direct syscall | Sí | No | No |
| Indirect syscall | Sí | No | No |
| Unhooking de ntdll | Sí | No | No |
| Kernel exploit / driver malicioso | Sí | Parcial | Parcial |

## Conclusión

Win32 API, ntdll y las syscalls no son tres nombres para lo mismo: son tres capas con responsabilidades distintas y superficies de ataque distintas. El código legítimo vive en Win32 API porque es estable y documentada. El malware que quiere evadir EDRs desciende hacia ntdll o directamente al kernel porque ahí los hooks son más difíciles de mantener.

Conocer esta arquitectura es el punto de partida para entender tanto las técnicas de evasión modernas como por qué los EDRs han tenido que mover su telemetría al kernel — y por qué esa carrera de armamentos entre detección y evasión sigue escalando.
