---
layout: single
title: "Calling conventions: cdecl, stdcall, fastcall y x64"
date: 2026-06-18
categories: [reversing, tutoriales]
tags: [calling-conventions, asm, x86, x64, reversing, windows, linux]
excerpt: "Cómo se pasan los argumentos, quién limpia la pila y cómo identificar la convención de llamada en el desensamblado."
permalink: /reversing/calling-conventions/
---

Esta es la entrega 5 de la serie [Reversing para principiantes](/reversing/).

En el [post anterior](/reversing/x64dbg-principiantes/) aprendimos a movernos por x64dbg con breakpoints y a parchear en caliente. Ahora toca entender algo que aparece constantemente al leer ensamblador: las *calling conventions*. Sin esto, las llamadas a funciones son ruido; con esto, puedes reconstruir firmas de funciones desconocidas.

---

## Por qué importan las calling conventions

Cuando el compilador genera una llamada a función tiene que resolver tres preguntas:

1. ¿Cómo se pasan los argumentos (pila, registros, cuáles)?
2. ¿Dónde va el valor de retorno?
3. ¿Quién restaura la pila tras la llamada: el *caller* o el *callee*?

La respuesta a esas tres preguntas define la calling convention. Si al hacer reversing asumes cdecl cuando en realidad es stdcall, calcularás mal el tamaño del stack frame y los argumentos te parecerán corrompidos.

---

## x86 (32 bits)

### cdecl

La convención predeterminada de C en x86 Linux (y en MSVC por defecto para funciones no-API). Los argumentos se empujan en la pila **de derecha a izquierda**. El *caller* limpia la pila tras el `call`.

```c
int suma(int a, int b);

// caller genera algo como:
push b        // segundo argumento primero
push a
call suma
add esp, 8    // caller limpia: 2 args × 4 bytes
```

En ensamblador el patrón reconocible es el `add esp, N` (o `sub esp, -N`) **inmediatamente después del `call`**:

```nasm
push 5
push 3
call suma
add  esp, 8       ; <-- esto es cdecl
mov  [resultado], eax
```

El valor de retorno está siempre en `EAX` (64 bits en `EDX:EAX`).

---

### stdcall

Convención de la API Win32. Los argumentos también se pasan en la pila de derecha a izquierda, pero el *callee* limpia la pila con `RET N`.

```nasm
; caller
push 5
push 3
call suma          ; no hay add esp después
; el RET 8 dentro de suma ya limpió la pila

; callee (suma)
suma:
  push ebp
  mov  ebp, esp
  mov  eax, [ebp+8]
  add  eax, [ebp+12]
  pop  ebp
  ret  8            ; <-- esto es stdcall: limpia 2×4 bytes
```

La señal en el desensamblado es un `RET N` con N > 0 al final del callee, y la *ausencia* de `add esp, N` en el caller tras el `call`.

---

### fastcall (Microsoft)

Los dos primeros argumentos van en `ECX` y `EDX`; el resto en la pila (derecha a izquierda). El callee limpia la pila (igual que stdcall para los argumentos en stack).

```nasm
; int mul(int a, int b, int c)
; a → ECX, b → EDX, c → pila

mov  ecx, 3       ; a
mov  edx, 5       ; b
push 7            ; c
call mul
; no hay add esp (el callee limpia el argumento en pila con RET 4)
```

Lo reconocerás porque los primeros dos `MOV reg, valor` antes del `call` usan específicamente ECX/EDX, y el callee empieza usando esos registros directamente sin leerlos del stack.

> GCC tiene su propio fastcall (`__attribute__((fastcall))`) que se comporta igual. Borland usó una variante llamada *register* que mete tres args en EAX, EDX, ECX.

---

### Tabla comparativa x86

| Convención | Args en registros | Orden en pila | Limpieza | Típico en |
|---|---|---|---|---|
| cdecl | — | derecha → izquierda | caller (`add esp, N`) | C/C++ Linux, MSVC |
| stdcall | — | derecha → izquierda | callee (`ret N`) | Win32 API |
| fastcall | ECX, EDX | derecha → izquierda | callee | COM, drivers, MSVC `/Gr` |
| thiscall | ECX (`this`) | derecha → izquierda | callee | Métodos C++ MSVC |

---

## x86-64 (64 bits)

En 64 bits hay dos ABIs predominantes que **no son compatibles entre sí**.

### Windows x64 ABI

Los primeros cuatro argumentos van en `RCX`, `RDX`, `R8`, `R9` (enteros/punteros) o `XMM0`–`XMM3` (float/double). El resto en la pila. El caller siempre reserva 32 bytes de *shadow space* (también llamado *home space*) en la pila antes del `call`, incluso si la función tiene cero argumentos.

```nasm
; MessageBoxA(NULL, "Hola", "Titulo", MB_OK)
sub  rsp, 40          ; 32 shadow + 8 alineación (16 bytes)
xor  ecx, ecx         ; hWnd = NULL
lea  rdx, [mensaje]   ; lpText
lea  r8,  [titulo]    ; lpCaption
xor  r9d, r9d         ; uType = MB_OK
call MessageBoxA
add  rsp, 40
```

El shadow space de 32 bytes es exclusivo de Windows. Si ves `sub rsp, 20h` (32 en decimal) al inicio de una función caller en un binario Windows, ya sabes que estás en x64 ABI.

### System V AMD64 ABI (Linux/macOS/BSD)

Los primeros **seis** argumentos enteros/punteros van en: `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`. Hasta ocho argumentos float/double en `XMM0`–`XMM7`. Sin shadow space. El caller debe alinear RSP a 16 bytes antes del `call`.

```nasm
; write(1, buf, len)
mov  rdi, 1           ; fd
lea  rsi, [buf]       ; buf
mov  rdx, [len]       ; count
call write
```

### Tabla comparativa x64

| ABI | Arg 1 | Arg 2 | Arg 3 | Arg 4 | Arg 5 | Arg 6 | Shadow space |
|---|---|---|---|---|---|---|---|
| Windows x64 | RCX | RDX | R8 | R9 | pila | pila | 32 bytes |
| SysV AMD64 | RDI | RSI | RDX | RCX | R8 | R9 | ninguno |

En ambas el valor de retorno entero está en `RAX`. Valores de 128 bits en `RDX:RAX`.

---

## Cómo identificarlas en la práctica

### Pasos al ver una llamada desconocida

1. **Mira los MOVs/PUSHes previos al `call`**. ¿Qué registros se cargan? ECX/EDX → fastcall. RCX/RDX/R8/R9 → Windows x64. RDI/RSI/RDX → SysV.

2. **Busca `add esp, N` o `add rsp, N` tras el `call`**. Si existe → cdecl (o Windows x64 deshaciendo el shadow). Si no → stdcall/fastcall.

3. **Mira el `RET` del callee**. `ret` solo → cdecl/SysV/Windows x64. `ret N` → stdcall o fastcall.

4. **Comprueba si hay `sub rsp, 20h` al inicio del caller**. Exclusivo de Windows x64 (shadow space).

### Ejercicio rápido

Carga cualquier DLL del sistema en Ghidra o x64dbg. Filtra por funciones exportadas y abre `CreateFileW`. Verás que los argumentos llegan en RCX, RDX, R8, R9 y pila: Windows x64 ABI en estado puro. Compara con un binario Linux de 64 bits donde `open(2)` recibirá el nombre en RDI.

---

## Caso real: thiscall en C++

Los métodos de clase en MSVC reciben el puntero `this` en ECX (x86) o RCX (x64 Windows, igual que el primer argumento). En x64 no hay diferencia visible con una función normal; en x86 el patrón es:

```nasm
; obj->metodo(arg1)
mov  ecx, [obj]       ; this
push arg1
call Clase::metodo
```

Si ves ECX cargarse con lo que parece un puntero a estructura justo antes de un `call`, probablemente es un método de clase.

---

## Siguientes pasos

Con esto puedes reconstruir prototipos de funciones desconocidas directamente desde el ensamblador. En la próxima entrega veremos **ofuscación básica**: XOR encoding, stack strings y control flow flattening, que son las técnicas más comunes que encontrarás en malware de nivel básico y en crackmes de dificultad media.
