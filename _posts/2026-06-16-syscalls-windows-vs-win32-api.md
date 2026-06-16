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
- **Syscall**: la instrucción de CPU (`syscall` en x64, `int 0x2e`/`sysenter` en sistemas antiguos) que provoca el cambio de privilegio de Ring 3 a Ring 0. Cada syscall tiene un número (el *System
