---
layout: single
title: "Anatomía de un binario ELF/PE: secciones, headers y entry point"
date: 2026-06-17
categories: [reversing, tutoriales]
tags: [elf, pe, binario, reversing, headers, secciones, entry-point, readelf, dumpbin]
excerpt: "Antes de abrir Ghidra necesitas entender lo que estás mirando: cómo está organizado un binario ELF o PE, qué son las secciones y por qué el entry point casi nunca es main."
permalink: /reversing/anatomia-binario-elf-pe/
---

Esta es la entrega 2 de la serie [Reversing para principiantes](/reversing/).

Si aún no has leído el primer post sobre [assembly x86](/reversing/asm-x86-principiantes/), hazlo antes de seguir: este asume que sabes leer ensamblador básico.

---

Cuando abres un binario en Ghidra, la primera pantalla que ves no es código: es una lista de secciones. Si no sabes lo que significan `.text`, `.data` o `IMAGE_NT_HEADERS`, estás navegando a ciegas. Este post desmonta la estructura de un binario ELF (Linux) y PE (Windows) para que entiendas lo que miras antes de tocar una instrucción.

## El formato es el mapa del tesoro

Un ejecutable no es una secuencia plana de bytes de instrucciones. Es un contenedor estructurado que el sistema operativo sabe interpretar para:

1. Cargar el código en memoria en las direcciones correctas.
2. Resolver dependencias de bibliotecas en tiempo de carga.
3. Establecer permisos de memoria por región (ejecutable, solo lectura, lectura-escritura).

El formato ELF se usa en Linux, Android, BSDs y la mayoría de sistemas Unix. El formato PE (Portable Executable) es el estándar en Windows: `.exe`, `.dll`, `.sys` son todos PE.

## ELF: Executable and Linkable Format

### El ELF Header

Los primeros 64 bytes de cualquier ELF de 64 bits son el ELF Header. Contiene:

| Campo | Tamaño | Descripción |
|-------|--------|-------------|
| `e_ident` | 16 bytes | Magic bytes `\x7fELF` + clase, endianness, versión |
| `e_type` | 2 bytes | `ET_EXEC` (ejecutable), `ET_DYN` (shared object/PIE), `ET_REL` (objeto relocalizable) |
| `e_machine` | 2 bytes | Arquitectura: `0x3E` = x86-64 |
| `e_entry` | 8 bytes | Dirección virtual del entry point |
| `e_phoff` | 8 bytes | Offset en el archivo del Program Header Table |
| `e_shoff` | 8 bytes | Offset en el archivo del Section Header Table |

```bash
readelf -h /bin/ls
```

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 ...
  Class:                             ELF64
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x6360
  ...
```

El `e_type` de `ET_DYN` no significa que el binario sea una biblioteca: los ejecutables compilados con `-fpie -pie` (la mayoría en sistemas modernos) también son de tipo `ET_DYN` porque el kernel los puede cargar en direcciones aleatorias (ASLR).

### Secciones vs Segmentos

Aquí hay una confusión habitual: ELF tiene dos vistas del mismo archivo.

**Secciones** — relevantes para el linker y para análisis estático. Agrupan código y datos por tipo semántico.

**Segmentos (Program Headers)** — relevantes para el loader del SO. Agrupan secciones que comparten permisos de memoria.

En reversing te importan las secciones. Las más frecuentes:

| Sección | Contenido | Permisos en memoria |
|---------|-----------|---------------------|
| `.text` | Código ejecutable | r-x |
| `.rodata` | Strings y constantes de solo lectura | r-- |
| `.data` | Variables globales inicializadas | rw- |
| `.bss` | Variables globales no inicializadas (no ocupa espacio en disco) | rw- |
| `.plt` | Procedure Linkage Table: trampolines para funciones de bibliotecas externas | r-x |
| `.got` / `.got.plt` | Global Offset Table: tabla de punteros resueltos por el loader | rw- |
| `.dynamic` | Información para el linker dinámico | rw- |
| `.symtab` / `.strtab` | Tabla de símbolos (ausente en binarios stripeados) | - |

```bash
readelf -S /bin/ls | grep -E '\.(text|data|bss|rodata|plt|got)'
```

### El entry point real

Cuando compilas `main()` en C, el entry point del binario no es `main`. Es `_start`, una función de la biblioteca de tiempo de ejecución de C (`crt1.o`, `crti.o`) que el linker añade automáticamente. `_start` inicializa el entorno (registros, punteros a `argc`/`argv`/`envp`), llama a `__libc_start_main`, y esta finalmente llama a `main`.

En Ghidra: busca la dirección de `e_entry` en el ELF header y ve ahí directamente. En un binario stripeado sin símbolos, la función que llama a `__libc_start_main` es `_start` aunque no esté etiquetada así. El primer argumento que le pasa (en `rdi` en x64) es el puntero a `main`.

## PE: Portable Executable

### DOS Header y NT Headers

Todo PE empieza con un DOS Header de 64 bytes, un legado de MS-DOS. Los primeros dos bytes son siempre `MZ` (magic de Mark Zbikowski). El campo `e_lfanew` en el offset 0x3C apunta al offset real de los NT Headers.

```
Offset 0x00: 4D 5A ("MZ")
...
Offset 0x3C: offset a IMAGE_NT_HEADERS
```

`IMAGE_NT_HEADERS` contiene:

- **Signature**: `PE\x00\x00` (4 bytes)
- **IMAGE_FILE_HEADER**: arquitectura, número de secciones, timestamp de compilación, flags
- **IMAGE_OPTIONAL_HEADER**: entry point, base de carga preferida, tamaño de imagen, data directories

El nombre "Optional" es engañoso: es obligatorio en ejecutables. Contiene el `AddressOfEntryPoint` (RVA — Relative Virtual Address — desde la base de carga).

```bash
dumpbin /headers programa.exe
```

En Linux con `wine` o directamente con `objdump`:

```bash
objdump -x programa.exe | head -60
```

### Secciones PE

| Sección | Equivalente ELF | Contenido |
|---------|-----------------|-----------|
| `.text` | `.text` | Código |
| `.rdata` | `.rodata` | Datos de solo lectura, imports, strings |
| `.data` | `.data` | Variables globales |
| `.bss` | `.bss` | Variables sin inicializar |
| `.idata` | `.got` + `.plt` | Import Address Table (IAT) |
| `.edata` | - | Export table (DLLs) |
| `.rsrc` | - | Recursos: iconos, strings de interfaz, versión |
| `.reloc` | - | Tabla de relocalizaciones para ASLR |

### Import Address Table (IAT)

La IAT es el equivalente PE de la GOT de ELF. Cuando el ejecutable llama a `CreateFileW` de `kernel32.dll`, en el código hay una instrucción como:

```nasm
call QWORD PTR [rip+0x12345]   ; [IAT entry de CreateFileW]
```

El loader de Windows resuelve ese puntero en tiempo de carga. En análisis estático, `.idata` te dice exactamente qué funciones de qué DLLs usa el binario —información de oro antes de empezar a desensamblar.

```bash
dumpbin /imports programa.exe
```

En Ghidra, el árbol de símbolos muestra las imports bajo `<EXTERNAL>`. Lista las imports antes de analizar: si ves `VirtualAlloc`, `WriteProcessMemory` y `CreateRemoteThread` juntas, ya sabes qué clase de código es.

### RVA vs VA vs Raw Offset

Confundir estos tres mata el análisis:

- **Raw offset**: posición física en el archivo en disco.
- **RVA (Relative Virtual Address)**: offset desde la imagen base en memoria.
- **VA (Virtual Address)**: dirección absoluta en memoria = ImageBase + RVA.

La `ImageBase` por defecto en PE64 es `0x140000000`. Un PE con ASLR activo puede cargarse en cualquier dirección, pero internamente los campos siempre usan RVA. Ghidra aplica el rebase automáticamente; si analizas con `objdump`, ten en cuenta que las direcciones son RVAs, no VAs absolutas.

## ELF vs PE: diferencias que importan al reversear

| Aspecto | ELF | PE |
|---------|-----|----|
| Magic | `\x7fELF` | `MZ` + `PE\x00\x00` |
| Resolución de imports | GOT/PLT en tiempo de carga/llamada | IAT resuelta en tiempo de carga |
| Relocalización | `.rela.dyn`, `.rela.plt` | `.reloc` (solo base relocation) |
| Lazy binding | Sí (PLT, puede desactivarse con `BIND_NOW`) | No (todo se resuelve al cargar) |
| Recursos embebidos | No estándar | `.rsrc` con estructura de árbol |
| Stripping | Elimina `.symtab`/`.strtab` | Elimina PDB path y debug info |
| Análisis de imports | `readelf -d` / `ldd` | `dumpbin /imports` / PE-bear |

El lazy binding de ELF es relevante en análisis dinámico: la primera vez que una función de biblioteca se llama, el PLT resuelve su dirección real y parchea la GOT. Si pones un breakpoint en `strcmp@plt` antes de la primera llamada, el puntero en la GOT aún apunta al resolver, no a `strcmp`. En el segundo call ya está resuelto.

## Herramientas de referencia rápida

**Linux / ELF:**
```bash
readelf -h binario          # ELF header
readelf -S binario          # secciones
readelf -d binario          # dynamic section (imports, RPATH)
readelf -l binario          # segmentos (program headers)
objdump -d -M intel binario # disassembly de .text
strings -n 8 binario        # strings de 8+ caracteres
```

**Windows / PE:**
```bash
dumpbin /headers prog.exe   # PE headers completos
dumpbin /imports prog.exe   # IAT
dumpbin /exports prog.dll   # export table
```

**Multiplataforma:**
- **PE-bear**: GUI para inspeccionar PE, editar secciones, ver la IAT resolvida.
- **pev** (`readpe`): herramientas de línea de comandos estilo `readelf` para PE, disponibles en Linux.
- **Ghidra / IDA**: parsean ambos formatos y muestran la información en el árbol de programa.

## Próximo paso

Con el mapa del binario claro —qué hay en `.text`, dónde está la IAT, qué hace `_start` antes de llegar a `main`— ya tiene sentido abrir Ghidra en serio. El siguiente post cubre exactamente eso: [tu primer crackme con Ghidra](/reversing/primer-crackme-ghidra/), desde la instalación hasta parchear un `strcmp` y hacer que la verificación de contraseña siempre pase.
