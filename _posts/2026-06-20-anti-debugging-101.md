---
layout: single
title: "Anti-debugging 101: IsDebuggerPresent, timing checks y cómo saltarlos"
date: 2026-06-20
categories: [reversing, tutoriales]
tags: [anti-debug, isdebuggerpresent, timing, x64dbg, ghidra, reversing, windows]
excerpt: "Las técnicas anti-debug más comunes en malware y protecciones comerciales: cómo funcionan, cómo las detectas en Ghidra y x64dbg, y cómo las neutralizas."
permalink: /reversing/anti-debugging-101/
---

Esta es la entrega 8 de la serie [Reversing para principiantes](/reversing/).

En la entrega anterior vimos [cómo el compilador transforma C en ensamblador](/reversing/c-a-asm/) con distintos niveles de optimización. Ahora llegamos al tema que convierte un crackme sencillo en un obstáculo real: las técnicas anti-debugging. El binario sabe que lo están analizando y cambia su comportamiento. Este post cubre las técnicas más frecuentes y la forma de neutralizarlas.

---

## Por qué existe el anti-debugging

Un binario que detecta un debugger puede hacer tres cosas: terminar, tomar un camino de código alternativo (falso), o corromper datos para que el análisis sea incorrecto. El efecto neto es el mismo: pierdes tiempo analizando código que no es el real.

Las técnicas se dividen en tres categorías:

| Categoría | Mecanismo | Ejemplos |
|-----------|-----------|---------|
| Detección de estado del proceso | Consultar flags del SO | `IsDebuggerPresent`, `NtQueryInformationProcess` |
| Detección por entorno | Artefactos que deja el debugger | Nombres de ventana, handles abiertos |
| Detección por comportamiento | El debugger ralentiza la ejecución | `RDTSC`, `GetTickCount`, excepciones |

---

## IsDebuggerPresent

La técnica más básica en Windows. Llama a una función de la API que consulta el flag `BeingDebugged` del PEB (Process Environment Block):

```c
if (IsDebuggerPresent()) {
    ExitProcess(1);
}
```

En ensamblador x64 suele verse como:

```nasm
call IsDebuggerPresent
test eax, eax
jnz  exit_or_fake_path
```

Si `IsDebuggerPresent` devuelve 1 (debugger presente), el salto `jnz` se toma. Lo que viene después —`ExitProcess`, código basura, loop infinito— es tu obstáculo.

### Qué es el PEB y por qué importa

El PEB es una estructura del proceso mantenida por el kernel. `IsDebuggerPresent` no hace magia: solo lee un byte:

```nasm
mov  rax, gs:[60h]    ; PEB desde el TEB
movzx eax, byte [rax+2]  ; BeingDebugged
ret
```

`gs:[60h]` apunta al PEB en x64 (`fs:[30h]` en x86). El byte en offset `+2` es `BeingDebugged`. Cuando un debugger adjunta el proceso, el kernel pone ese byte a 1.

### Cómo saltarlo

**Método 1 — parchear el salto en x64dbg:**

Pon un breakpoint en la llamada a `IsDebuggerPresent`. Cuando pare, modifica el registro `EAX` a 0 antes de que el `test`/`jnz` se ejecute, o cambia el flag `ZF` directamente en el panel de registros.

También puedes ir a la instrucción `jnz` y cambiarla a `jz` (cambia un byte: `75` → `74`) para que el salto nunca se tome.

**Método 2 — parchear el PEB directamente:**

En x64dbg, abre la ventana de memoria, navega al PEB (el registro `GS` en x64 apunta al TEB, suma 0x60 para llegar al PEB, el byte `BeingDebugged` está en offset +2) y escribe un 0.

```
Memory → Go to expression: gs:[60] + 2
Patch: byte → 0x00
```

Después de esto, `IsDebuggerPresent` devolverá 0 aunque estés en el debugger.

**Método 3 — plugin ScyllaHide:**

[ScyllaHide](https://github.com/x64dbg/ScyllaHide) es un plugin para x64dbg que parchea automáticamente el PEB y docenas de otras técnicas anti-debug con un solo clic. Es lo que usarás en la práctica para no perder tiempo.

---

## NtQueryInformationProcess

Una capa más profunda. Llama directamente a la API de NT pasando `ProcessDebugPort` (clase 7) o `ProcessDebugFlags` (clase 31):

```c
DWORD debug_port = 0;
NtQueryInformationProcess(
    GetCurrentProcess(),
    ProcessDebugPort,       // clase 7
    &debug_port,
    sizeof(debug_port),
    NULL
);
if (debug_port != 0) {
    // debugger detectado
}
```

`ProcessDebugPort` devuelve un valor distinto de cero si el proceso tiene un debugger adjunto. En ensamblador busca la secuencia:

```nasm
mov  ecx, 7          ; ProcessDebugPort
push rcx
call NtQueryInformationProcess
cmp  [result], 0
jne  detected
```

ScyllaHide también lo maneja. Si lo encuentras manualmente, en x64dbg puedes poner un hardware breakpoint sobre la variable `debug_port` para ver cuándo se escribe y modificar el valor justo después.

---

## Timing checks

El debugger introduce latencia. Las instrucciones que ejecutas manualmente —paso a paso— tardan miles de veces más que en ejecución libre. Los timing checks miden ese delta:

### RDTSC

`RDTSC` (Read Time-Stamp Counter) lee el contador de ciclos del procesador. La comparación de dos lecturas separadas por una región de código revela si hay un debugger:

```nasm
rdtsc
mov  esi, eax           ; guarda timestamp inicial
; ... código a medir ...
rdtsc
sub  eax, esi           ; delta = timestamp_final - timestamp_inicial
cmp  eax, 0xFF0000      ; umbral: ~16M ciclos
ja   debugger_detected  ; demasiado lento → debugger
```

En ejecución normal, el delta es pequeño (cientos o miles de ciclos). Con un debugger y pasos manuales, el delta es enorme.

**Cómo saltarlo:** Pon un breakpoint en la instrucción `cmp` o `ja` al final y modifica `EAX` a un valor menor que el umbral antes de que se ejecute la comparación. También puedes nopear la instrucción `ja`.

### GetTickCount

La versión de Win32, más lenta pero más portable:

```c
DWORD t1 = GetTickCount();
// código crítico
DWORD t2 = GetTickCount();
if ((t2 - t1) > 300) {  // más de 300ms → probable debugger
    ExitProcess(1);
}
```

En Ghidra lo reconocerás por las dos llamadas a `GetTickCount` con una operación `SUB` y una comparación entre medias. La estrategia es la misma: modifica el resultado de la resta o el salto condicional.

---

## Detección por ventana de debugger

Algunos binarios buscan ventanas con títulos conocidos de debuggers:

```c
if (FindWindowA("OllyDbg", NULL) ||
    FindWindowA("x64dbg", NULL)  ||
    FindWindowA("WinDbg", NULL)) {
    // debugger presente
}
```

En Ghidra es fácil de localizar porque los strings de los nombres de ventana aparecen en `.rdata`. Busca referencias a `FindWindowA` o `FindWindowExA`.

**Cómo saltarlo:** Renombra la ventana del debugger (en x64dbg: opciones de apariencia), o en el código parchea el salto condicional posterior a la llamada.

---

## CheckRemoteDebuggerPresent

Similar a `IsDebuggerPresent` pero permite comprobar otro proceso. Cuando se llama sobre sí mismo, es equivalente:

```c
BOOL being_debugged = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &being_debugged);
if (being_debugged) {
    // ...
}
```

ScyllaHide lo intercepta. Manualmente: breakpoint en `CheckRemoteDebuggerPresent`, modifica el buffer de salida a 0 antes de que el código lo lea.

---

## Flujo de trabajo en x64dbg

Cuando abres un binario y sospechas que tiene anti-debug, el proceso es:

```
1. Activa ScyllaHide antes de iniciar el proceso
   → Plugins → ScyllaHide → Options → marcar todas las opciones relevantes

2. Pon un breakpoint en los puntos de entrada habituales:
   bp IsDebuggerPresent
   bp CheckRemoteDebuggerPresent
   bp NtQueryInformationProcess
   bp GetTickCount

3. Ejecuta (F9) y observa dónde para

4. En cada parada, examina el contexto:
   - ¿Qué argumentos entran?
   - ¿Qué hace el código con el valor de retorno?
   - ¿Hay un salto condicional inmediatamente después?

5. Decide: ¿parcheas el registro, el flag, o la instrucción de salto?
```

---

## Análisis estático en Ghidra

Antes de ejecutar nada, Ghidra te da el mapa completo:

1. **Busca las funciones API**: `Window → Symbol References` o busca en el árbol de símbolos `IsDebuggerPresent`, `NtQueryInformationProcess`, `GetTickCount`, `FindWindowA`.

2. **Sigue las referencias**: haz doble clic en el símbolo para ir a la importación, luego "References → Show References to" para ver todos los puntos donde se llama.

3. **Analiza el flujo posterior**: desde cada call site, el decompilador de Ghidra (`F`) muestra el `if` en pseudocódigo C. Identifica qué rama es la "buena" (la que continúa el código legítimo).

4. **Documenta antes de parchear**: anota la dirección del salto y qué cambio necesitas. Parchar en Ghidra (Assembly → Patch Instruction) genera un binario modificado que puedes ejecutar sin debugger.

---

## Comparativa de técnicas y contramedidas

| Técnica | Detección en Ghidra | Parche en x64dbg | ScyllaHide |
|---------|--------------------|--------------------|------------|
| `IsDebuggerPresent` | Referencias al símbolo | Modificar EAX o ZF | Sí |
| `NtQueryInformationProcess` | Referencias + clase 7/31 | Parchear buffer de salida | Sí |
| RDTSC timing | `rdtsc` + `cmp` + umbral | Modificar delta o nopear salto | Parcial |
| `GetTickCount` timing | Dos calls + `sub` + `cmp` | Modificar resultado resta | No |
| `FindWindowA` | Strings de nombres de debugger | Renombrar ventana o parchear salto | Parcial |
| `CheckRemoteDebuggerPresent` | Referencias al símbolo | Parchear buffer de salida | Sí |

---

## Practica con un binario real

La forma más eficiente de consolidar esto es un crackme con anti-debug habilitado. En [crackmes.one](https://crackmes.one) filtra por dificultad 3-4 y busca los que en la descripción mencionan "anti-debug" o "protection". Proceso:

```bash
# Reconocimiento inicial
strings crackme.exe | grep -iE '(debug|window|tick|rdtsc)'
pescan crackme.exe   # o: pecheck, diec
```

Si `strings` no da nada interesante pero el binario hace algo con debuggers, busca `RDTSC` en el desensamblado (en x64dbg: busca todos los comandos con `rip rdtsc` en la ventana de CPU).

---

## Con esto termina la serie

Esta ha sido la última entrega de [Reversing para principiantes](/reversing/). El camino cubierto:

1. [Ensamblador x86 desde cero](/reversing/asm-x86-principiantes/)
2. [Anatomía de un binario ELF/PE](/reversing/anatomia-binario-elf-pe/)
3. [Tu primer crackme con Ghidra](/reversing/primer-crackme-ghidra/)
4. [x64dbg para principiantes](/reversing/x64dbg-principiantes/)
5. [Calling conventions](/reversing/calling-conventions/)
6. [Ofuscación básica](/reversing/ofuscacion-basica/)
7. [De C a ASM y vuelta](/reversing/c-a-asm/)
8. Anti-debugging 101 ← estás aquí

El siguiente nivel natural: análisis de malware real (empezando por muestras en [MalwareBazaar](https://bazaar.abuse.ch)) y técnicas avanzadas de anti-análisis como virtualización de código (VMProtect, Themida). Pero eso es material para otra serie.
