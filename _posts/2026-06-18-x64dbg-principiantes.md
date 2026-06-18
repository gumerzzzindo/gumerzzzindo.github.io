---
layout: single
title: "x64dbg para principiantes: breakpoints, stepping y parches en caliente"
date: 2026-06-18
categories: [reversing, tutoriales]
tags: [x64dbg, debugging, breakpoints, patching, análisis-dinámico, reversing, windows]
excerpt: "Instala x64dbg, aprende a poner breakpoints, a navegar instrucción a instrucción y a parchear bytes mientras el programa corre."
permalink: /reversing/x64dbg-principiantes/
---

Esta es la entrega 4 de la serie [Reversing para principiantes](/reversing/).

El post anterior cubrió [análisis estático con Ghidra](/reversing/primer-crackme-ghidra/): descompilación, renombrar funciones y parchear un strcmp sobre la copia interna de Ghidra. El análisis estático te dice qué hay escrito en el binario. El análisis dinámico —ejecutar el binario bajo un debugger— te dice qué hace realmente en tiempo de ejecución: qué valores toman las variables, qué rutas de código se ejecutan, qué llama a qué y en qué orden.

x64dbg es el debugger de referencia en Windows para binarios de usuario: código abierto, activamente mantenido, con plugin ecosystem sólido y mejor interfaz que OllyDbg, a quien reemplaza en la práctica.

---

## Instalación

Descarga el ZIP de [x64dbg.com](https://x64dbg.com/). No hay instalador. Descomprime y ejecuta:

- `x64dbg.exe` para binarios de 64 bits
- `x32dbg.exe` para binarios de 32 bits

La primera vez aparece el selector de arquitectura. Selecciona la que corresponda a tu objetivo. Para el resto del post usamos `x64dbg` con un binario de 64 bits.

---

## La interfaz en cinco paneles

| Panel | Contenido |
|-------|-----------|
| **Disassembly** | Instrucciones ASM del código que se está ejecutando. La flecha amarilla marca la instrucción actual (RIP). |
| **Registers** | Estado de todos los registros (RAX, RBX, RIP, RSP…) y flags (ZF, CF, SF…). Se resaltan en rojo los que cambian en cada paso. |
| **Stack** | Contenido del stack en torno a RSP. |
| **Memory Map** | Regiones de memoria del proceso: código, heap, DLLs cargadas, etc. |
| **Log / Info** | Mensajes del debugger, hits de breakpoints, excepciones. |

La barra inferior muestra la dirección actual, el módulo y el offset dentro de él.

---

## Cargar un binario

**File → Open** (o arrastrar el ejecutable sobre la ventana). x64dbg carga el proceso y pausa en el entry point del sistema —normalmente dentro de `ntdll`— antes de que el código del usuario haya ejecutado nada.

Para llegar directamente al `main` o `WinMain` del binario:

1. Pulsa `F9` (Run) para dejar que el proceso avance hasta el entry point del binario propio. x64dbg tiene un breakpoint automático en el OEP (*Original Entry Point*) activado por defecto en *Options → Preferences → Events*.
2. Alternativamente, busca la función: *Symbols* → selecciona el módulo principal → busca `main` o el export que te interese → clic derecho → *Follow in Disassembler*.

---

## Breakpoints de software

Un breakpoint de software reemplaza el primer byte de la instrucción destino con `0xCC` (`INT 3`). Cuando la CPU lo ejecuta, el sistema operativo envía una excepción de debug y x64dbg toma el control.

Para poner uno:

- **Desde el panel Disassembly**: haz clic en la instrucción y pulsa `F2`. La línea se resalta en rojo.
- **Desde la barra de comandos** (inferior): `bp <dirección>` o `bp <símbolo>`.

```
bp strcmp
bp 0x00401234
```

Para listar todos los breakpoints activos: pestaña **Breakpoints** en el panel inferior.

Para desactivar sin borrar: doble clic sobre el breakpoint en la lista → toggle *Active*.

---

## Breakpoints de hardware

Los hardware breakpoints usan registros de debug del procesador (DR0–DR3). No modifican el código, así que no los detectan los anti-tamper que verifican integridad del texto. Solo puedes tener cuatro activos simultáneamente.

```
bph <dirección>         # break on execute
bphm <dirección> r 4   # break on read, 4 bytes
bphm <dirección> w 2   # break on write, 2 bytes
```

Son especialmente útiles para rastrear cuándo se escribe o lee una variable en memoria: pones un hardware breakpoint de escritura sobre la dirección de la variable y x64dbg para cada vez que algo la toca.

---

## Navegar instrucción a instrucción

| Tecla | Acción |
|-------|--------|
| `F7` | **Step Into** — ejecuta una instrucción. Si es un `CALL`, entra en la función llamada. |
| `F8` | **Step Over** — ejecuta una instrucción. Si es un `CALL`, ejecuta la función completa y para al volver. |
| `F4` | **Run to cursor** — ejecuta hasta la instrucción donde está el cursor, sin poner breakpoint. |
| `F9` | **Run** — continúa la ejecución hasta el siguiente breakpoint o hasta que el proceso termine. |
| `Ctrl+F9` | **Execute till return** — ejecuta hasta el `RET` de la función actual. |
| `Alt+F9` | **Execute till user code** — salta instrucciones de sistema/DLL hasta volver a código del módulo principal. |

La diferencia entre Step Into y Step Over es la que más confunde al principio. Regla práctica: usa Step Over para funciones de biblioteca que ya entiendes (`printf`, `malloc`); usa Step Into para funciones propias que quieres analizar.

---

## Leer registros y memoria mientras depuras

En el panel **Registers**, cada valor es interactivo:

- Doble clic sobre un registro para cambiar su valor manualmente.
- Clic derecho → *Follow in Dump* para volcar la memoria a la que apunta.
- Las flags (ZF, CF, OF…) se pueden toggle con doble clic. Esto permite forzar que un salto condicional tome o no tome el camino que te interesa, sin modificar el binario.

En el panel **Dump** puedes inspeccionar memoria arbitraria:

```
dump <dirección>
dump rsp
dump rax
```

---

## Ejemplo práctico: el mismo crackme

Usa el `crackme` compilado en el post anterior (o el equivalente en Windows):

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <contrasena>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "s3cr3t0") == 0) {
        puts("Acceso concedido");
        return 0;
    }
    puts("Contrasena incorrecta");
    return 1;
}
```

Compila con MinGW o con MSVC en Windows. Carga el exe en x64dbg.

**Objetivo**: llegar al `strcmp`, ver la comparación y forzar que siempre tome el camino de "Acceso concedido".

### Paso 1: encontrar el strcmp

En la pestaña **Symbols**, selecciona el módulo principal. Si el binario está enlazado dinámicamente contra `msvcrt.dll` o `ucrtbase.dll`, `strcmp` aparecerá como import. Clic derecho → *Follow in Disassembler*.

Alternativamente, usa la búsqueda de referencias: *Right click en el panel Disassembly → Search for → Current module → Intermodular calls* → busca `strcmp`.

### Paso 2: breakpoint en strcmp

```
bp strcmp
```

Pulsa `F9`. El proceso corre y x64dbg para al entrar en `strcmp`. El panel de Call Stack muestra de dónde vino la llamada. Pulsa `Ctrl+F9` (Execute till return) para dejar que `strcmp` termine y volver al punto justo después del `CALL`.

Ahora RIP apunta a la instrucción que sigue al `CALL strcmp`: típicamente un `TEST EAX, EAX` o un `CMP EAX, 0`.

### Paso 3: inspeccionar el resultado

En **Registers**, mira EAX justo después de que `strcmp` retorna. Si pasaste una contraseña incorrecta, EAX ≠ 0. La instrucción siguiente será algo como:

```nasm
TEST   EAX, EAX
JNZ    <etiqueta_incorrecta>
```

`JNZ` salta si ZF=0, es decir, si las cadenas no son iguales.

### Paso 4: forzar el salto — sin parchear

La forma más rápida para probar: con el proceso pausado justo antes del `JNZ`, ve al panel Registers y haz doble clic sobre la flag **ZF** para cambiarla de 0 a 1. Ahora `JNZ` no saltará y la ejecución caerá al bloque de "Acceso concedido". Pulsa `F9`.

Esto no modifica el binario en disco. Es un parche en memoria solo para esta ejecución.

---

## Parches en caliente (modificar bytes en memoria)

Para cambiar el comportamiento de forma persistente durante la sesión, o para generar un parche exportable:

1. Haz clic sobre la instrucción `JNZ` en el panel Disassembly.
2. Clic derecho → **Assemble** (o pulsa `Space`).
3. Escribe `NOP` y acepta. x64dbg reemplaza `JNZ rel8` (2 bytes) con dos `NOP` (2×1 byte).

El cambio se aplica inmediatamente en la memoria del proceso. Si el proceso vuelve a pasar por esa instrucción, verá los NOPs.

Para exportar el parche al binario en disco:

*File → Patch File* → x64dbg muestra una lista de todos los bytes modificados con el valor original y el nuevo. Selecciona todos y pulsa *Patch File*. Guarda una copia del exe parcheado.

```
Original:  75 0A     ; JNZ +10
Parcheado: 90 90     ; NOP NOP
```

---

## Breakpoints condicionales

En vez de parar en cada hit de un breakpoint, puedes filtrar por condición:

```
bp strcmp
bpcnd strcmp "strcmp==0"
```

O desde la interfaz: clic derecho sobre un breakpoint en la lista → *Edit* → campo *Condition*. La sintaxis usa el lenguaje de expresiones de x64dbg, que acepta registros, memoria y operadores estándar.

Ejemplo: parar en un breakpoint solo si RCX apunta a una cadena que empieza por "admin":

```
mem.readbyte(rcx) == 0x61 && mem.readbyte(rcx+1) == 0x64
```

Los breakpoints condicionales son críticos cuando el punto de interés se llama miles de veces y solo quieres inspeccionar un caso específico.

---

## Tracing

x64dbg puede registrar todas las instrucciones ejecutadas en un rango:

*Debug → Trace → Trace Into* — ejecuta en modo trace hasta que se cumpla una condición de parada. El resultado es un log de todas las instrucciones con el estado de los registros en cada paso.

El trace es costoso en tiempo pero insustituible cuando el flujo de control es tan dinámico que los breakpoints normales no alcanzan.

---

## Plugins esenciales

x64dbg tiene un sistema de plugins. Los más usados:

| Plugin | Función |
|--------|---------|
| **ScyllaHide** | Oculta el debugger de las técnicas anti-debug más comunes (IsDebuggerPresent, NtQueryInformationProcess, etc.) |
| **xAnalyzer** | Añade comentarios automáticos en llamadas a API de Windows |
| **ret-sync** | Sincroniza x64dbg con IDA o Ghidra en tiempo real: lo que marcas en el debugger aparece en el descompilador |

Para instalar: copia el `.dp64` (o `.dp32`) en la carpeta `plugins/` de x64dbg. Se cargan al inicio.

---

## Próximo paso

Con Ghidra para análisis estático y x64dbg para análisis dinámico tienes el flujo de trabajo básico completo. El siguiente obstáculo real es entender cómo el compilador gestiona las convenciones de llamada: qué registros llevan los argumentos, quién limpia el stack, cómo identificar los límites de una función en ASM. El siguiente post cubre [calling conventions: cdecl, stdcall, fastcall y la convención x64](/reversing/calling-conventions/).
