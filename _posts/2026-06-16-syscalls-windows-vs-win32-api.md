---
layout: single
title: "Syscalls de Windows vs Win32 API: por qué nadie llama directamente al kernel"
date: 2026-06-16
categories: [tutoriales, malware]
tags: [windows-internals, syscalls, win32api, ntdll, ntoskrnl, seguridad-en-capas, edr, evasion]
excerpt: "Win32 API, ntdll.dll y syscalls nativas: que hace cada capa, por que el codigo normal nunca toca el kernel directamente, y si Windows tiene seguridad por capas como un kernel tradicional."
permalink: /tutoriales/syscalls-windows-vs-win32-api/
---
Cuando se escribe `CreateFileW()` en C, o `Process.Start()` en .NET, en realidad no se está hablando con el kernel. Se está hablando con una API de usuario que, varias capas más abajo, termina pidiéndole permiso al kernel para hacer el trabajo real. Entender esas capas explica por qué el malware moderno casi siempre intenta saltárselas, y por qué eso es exactamente lo que vigila un EDR.

---

## Las tres capas, de arriba a abajo

```
[ Tu programa ]
       │  CreateFileW(), VirtualAlloc(), WriteProcessMemory()...
       ▼
[ Win32 API ]               kernel32.dll, advapi32.dll, user32.dll...
       │  valida parámetros, traduce a formato NT, gestiona compatibilidad
       ▼
[ Native API ]              ntdll.dll
       │  NtCreateFile(), NtAllocateVirtualMemory()...
       │  prepara el registro de la CPU y ejecuta la instrucción syscall/sysenter
       ▼
[ Syscall / transición a kernel ]
       │  cambio de anillo: Ring 3 (usuario) → Ring 0 (kernel)
       ▼
[ ntoskrnl.exe — el kernel ]
       │  comprueba permisos, accede al objeto real, ejecuta la operación
       ▼
[ Hardware / drivers ]
```

Tres nombres, tres trabajos distintos:

- **Win32 API**: la capa "amigable". DLLs como `kernel32.dll`, `user32.dll`, `advapi32.dll`. Documentada públicamente, estable entre versiones de Windows, con miles de funciones para todo: ficheros, red, hilos, registro, UI.
- **Native API / NT API**: vive en `ntdll.dll`. Son las funciones `Nt*`/`Zw*` (`NtCreateFile`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`...). Es la capa que realmente prepara la llamada al kernel. Mayormente no documentada oficialmente, y *puede* cambiar entre versiones de Windows.
- **Syscall**: la instrucción de CPU (`syscall` en x64, `int 0x2e`/`sysenter` en sistemas antiguos) que provoca el cambio de privilegio de Ring 3 a Ring 0. Cada syscall tiene un número (el *System Service Number*, SSN) que identifica qué operación se quiere ejecutar en el kernel.

---

## Qué pasa exactamente cuando llamas a CreateFileW

Siguiendo el flujo con un ejemplo concreto:

1. Tu código llama a `CreateFileW()` en `kernel32.dll`.
2. `kernel32.dll` valida parámetros, convierte el path a formato NT (`\??\C:\ruta`), y llama a `NtCreateFile()` en `ntdll.dll`.
3. El stub de `NtCreateFile` en `ntdll.dll` hace algo parecido a esto:

```nasm
; NtCreateFile stub en ntdll.dll (x64, Windows 10/11)
mov r10, rcx          ; syscall convention: primer argumento a r10
mov eax, 0x55         ; SSN de NtCreateFile (varía por versión de Windows)
syscall               ; transición a Ring 0
ret
```

4. La CPU entra en kernel mode. El *System Service Dispatcher* (`KiSystemCall64` en `ntoskrnl.exe`) recibe el SSN, busca la función correspondiente en la *System Service Descriptor Table* (SSDT), y la ejecuta.
5. El kernel comprueba permisos, resuelve el objeto en el *Object Manager*, y hace el trabajo real.
6. El resultado vuelve a Ring 3 como `NTSTATUS`.

El SSN es simplemente un índice en una tabla. No hay nombre de función ni string de por medio — solo un número entero que el kernel mapea a una función interna.

---

## Por qué el código normal no usa syscalls directas

Dos razones principales:

**Portabilidad**: el SSN de `NtCreateFile` en Windows 7 es distinto al de Windows 10 y al de Windows 11. Si hardcodeas el número, tu programa petará o hará algo inesperado en otra versión. `ntdll.dll` abstrae eso: los stubs siempre tienen el SSN correcto para la versión en ejecución.

**Estabilidad de API**: Microsoft garantiza que la Win32 API es estable. La Native API (`Nt*`) no está garantizada. Microsoft puede cambiar los parámetros, el comportamiento, o los SSN en cualquier update. Programar contra `kernel32.dll` te da compatibilidad hacia adelante; programar contra `ntdll.dll` directamente, o peor, contra SSNs hardcodeados, no.

---

## ¿Windows tiene seguridad por capas "de verdad"?

Sí, aunque de forma diferente a lo que se esperaría de un sistema tipo Unix.

El modelo de anillos de la CPU (Ring 0 / Ring 3) es la separación real y obligatoria. El kernel corre en Ring 0 y tiene acceso total al hardware y a la memoria. El código de usuario corre en Ring 3 y no puede acceder directamente a nada privilegiado: la CPU lo impide a nivel hardware. La única forma de cruzar esa frontera es a través de una syscall, que pasa por el kernel, que decide si la operación está permitida.

Las capas por encima (Win32 API → ntdll → syscall) son capas de *abstracción y compatibilidad*, no de seguridad en sí mismas. La seguridad real la impone el kernel cuando recibe la syscall:

- **Access Control**: ¿tiene el proceso el `HANDLE` necesario con los permisos correctos?
- **Token/privilegios**: ¿tiene el token del proceso el privilegio requerido (p. ej. `SeDebugPrivilege`)?
- **Integrity Level**: ¿el nivel de integridad del proceso permite la operación sobre el objeto?
- **Object Security Descriptor**: ¿la DACL del objeto permite al SID del proceso realizar esa acción?

Todo eso lo comprueba el kernel, no la Win32 API. `kernel32.dll` puede hacer alguna validación básica de parámetros, pero no es donde vive la seguridad.

---

## Por qué le importa esto a un EDR

Un EDR tradicional basado en *user-mode hooks* coloca detours en las funciones de `ntdll.dll`. Cuando un proceso llama a `NtCreateFile`, en realidad está ejecutando primero código del EDR que analiza los parámetros, decide si es sospechoso, y luego salta a la función original.

El problema es que ese hook vive en user mode, en el espacio de memoria del propio proceso. Y si el malware lo sabe, puede saltárselo de varias formas:

- **Direct syscalls**: en vez de llamar al stub de `ntdll.dll`, calcular el SSN directamente (resolviendo el stub en memoria o usando técnicas como *Hell's Gate*, *Halo's Gate*, *Tartarus' Gate*) y ejecutar la instrucción `syscall` desde el propio código malicioso. El hook de `ntdll` nunca se ejecuta.
- **Unhooking**: restaurar el código original de `ntdll.dll` en memoria (cargando una copia limpia desde disco, o desde `KnownDlls`, o desde la sección de la DLL en otro proceso).
- **Indirect syscalls**: usar el `syscall` de un stub legítimo de `ntdll` pero controlando el SSN desde fuera, para que el EDR vea la instrucción venir de `ntdll` pero sin pasar por el hook.

Los EDRs modernos contrarrestan esto con kernel-mode drivers (protegidos por PatchGuard y ELAM) que no pueden ser unhooked desde user mode, y con ETW (Event Tracing for Windows) que captura eventos directamente en kernel sin pasar por los stubs de ntdll.

---

## Resumen

| Capa | Dónde vive | Para qué sirve | ¿Cambia entre versiones? |
|---|---|---|---|
| Win32 API | `kernel32.dll`, `user32.dll`... | Abstracción amigable y estable | No (garantizado por MS) |
| Native API | `ntdll.dll` | Preparar y ejecutar la syscall | A veces |
| SSN | Hardcoded en el stub de ntdll | Identificar la operación en el kernel | Sí, por versión y build |
| Kernel | `ntoskrnl.exe` | Ejecutar la operación real, imponer seguridad | Interno |

El flujo normal `CreateFileW → NtCreateFile → syscall → kernel` existe por razones de diseño y compatibilidad, no por seguridad. La seguridad real la impone el kernel al recibir la syscall. Y eso es exactamente el motivo por el que el malware sofisticado intenta llegar al kernel lo más directamente posible, evitando todas las capas intermedias donde los EDRs ponen sus ojos.
