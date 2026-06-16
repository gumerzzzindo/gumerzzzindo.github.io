---
layout: single
title: "Assembly x86 para principiantes: registros, instrucciones y tu primer disassembly"
date: 2026-06-16
categories: [tutoriales, reversing]
tags: [assembly, x86, x64, reverse-engineering, objdump, gdb, registros]
excerpt: "Introduccion practica al ensamblador x86/x64: registros, instrucciones basicas y como leer tu primer disassembly con objdump."
permalink: /reversing/asm-x86-principiantes/
header:
  image: "https://upload.wikimedia.org/wikipedia/commons/thumb/6/65/Intel_80486DX2_top.jpg/1920px-Intel_80486DX2_top.jpg"
  caption: "Intel 80486DX2 — Wikimedia Commons"

---

Todo el contenido de ingeniería inversa de este blog (syscalls de Windows, el kill-switch de WannaCry, drivers empaquetados) asume que sabes leer ensamblador. Este post es el punto de partida real: el primer paso antes de abrir Ghidra o x64dbg en serio. Si ya sabes qué es un registro y por qué `mov eax, 1` no es magia, puedes saltártelo.

## Por qué aprender assembly si ya existe el decompilador

Ghidra e IDA generan pseudocódigo en C que es más legible que el ensamblador puro, pero ese pseudocódigo es una interpretación, no la verdad. Cuando el decompilador se confunde —con código empaquetado, optimizaciones agresivas o trucos anti-análisis— lo que queda es ensamblador crudo. Sin saber leerlo, ahí se acaba el análisis.

## Registros: la memoria más rápida que existe

En x86_64 hay 16 registros de propósito general de 64 bits: `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `rsp`, y `r8`-`r15`. Cada uno tiene versiones más pequeñas que ocupan los mismos bits:

| 64 bits | 32 bits | 16 bits | 8 bits |
|---------|---------|---------|--------|
| `rax`   | `eax`   | `ax`    | `al`   |
| `rbx`   | `ebx`   | `bx`    | `bl`   |
| `rcx`   | `ecx`   | `cx`    | `cl`   |

Es decir, `eax` no es un registro distinto de `rax`: son los 32 bits bajos del mismo registro de 64. Esto importa al leer código de 32 y 64 bits mezclado, algo habitual en binarios legacy o en compatibilidad WoW64.

Algunos registros tienen un rol semi-fijo por convención (no por hardware, salvo `rsp`):

- **`rax`** — valor de retorno de una función.
- **`rsp`** — puntero a la cima de la pila (stack pointer). Este sí es especial a nivel de hardware: `push`/`pop`/`call`/`ret` lo modifican implícitamente.
- **`rbp`** — puntero base del stack frame actual (cuando no se omite con `-fomit-frame-pointer`).
- **`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`** — primeros seis argumentos de una función en la convención System V (Linux/macOS). En Windows x64 el orden es `rcx`, `rdx`, `r8`, `r9`.

## Las instrucciones que vas a ver el 90% del tiempo

```asm
mov eax, 5        ; copia el valor 5 al registro eax
mov ebx, eax      ; copia el contenido de eax a ebx
add eax, ebx      ; eax = eax + ebx
sub eax, 1        ; eax = eax - 1
cmp eax, ebx      ; compara eax con ebx (resta interna, no guarda resultado)
je  etiqueta      ; salta si la comparación anterior dio igualdad
jne etiqueta      ; salta si NO dio igualdad
jmp etiqueta      ; salto incondicional
call funcion      ; llama a una función (push de la dirección de retorno + jmp)
ret               ; vuelve al llamador (pop de la dirección de retorno + jmp)
push rax          ; mete rax en la pila, decrementa rsp
pop  rax          ; saca el tope de la pila a rax, incrementa rsp
```

`cmp` seguido de un salto condicional (`je`, `jne`, `jg`, `jl`...) es el equivalente a un `if` en C. Reconocer este patrón es el 80% de leer la lógica de un binario.

## Tu primer disassembly con objdump

Compila algo trivial:

```c
// suma.c
int suma(int a, int b) {
    return a + b;
}
```

```bash
gcc -O0 -c suma.c -o suma.o
objdump -d -M intel suma.o
```

Salida aproximada (sintaxis Intel, la que se usa en este blog):

```asm
0000000000000000 <suma>:
   0:	55                   push   rbp
   1:	48 89 e5             mov    rbp,rsp
   4:	89 7d ec             mov    DWORD PTR [rbp-0x14],edi
   7:	89 75 e8             mov    DWORD PTR [rbp-0x18],esi
   a:	8b 55 ec             mov    edx,DWORD PTR [rbp-0x14]
   d:	8b 45 e8             mov    eax,DWORD PTR [rbp-0x18]
  10:	01 d0                add    eax,edx
  12:	5d                   pop    rbp
  13:	c3                   ret
```

Línea a línea: `push rbp` + `mov rbp,rsp` monta el stack frame (el "prólogo" clásico de cualquier función sin optimizar). Los dos `mov` siguientes guardan los argumentos `edi` (primer argumento, `a`) y `esi` (segundo argumento, `b`) en variables locales en la pila. Luego se cargan de vuelta en `edx` y `eax`, se suman con `add eax,edx`, y el resultado queda en `eax` —que es justo el registro de retorno. `pop rbp` + `ret` es el "epílogo".

Compara esto con `gcc -O2 -c suma.c -o suma.o` y vuelve a desensamblar: la función entera se reduce a `lea eax,[rdi+rsi]` y `ret`. El compilador se da cuenta de que no necesita ni stack frame ni variables locales para algo tan simple. Ver la misma función en ambos niveles de optimización es el ejercicio más útil para empezar a reconocer patrones reales en binarios compilados en release.

## Sintaxis Intel vs AT&T

`objdump` por defecto usa sintaxis AT&T (`mov %eax, %ebx`, operandos en orden inverso, prefijo `%` en registros y `$` en inmediatos). La flag `-M intel` cambia a sintaxis Intel, que es la que usan Ghidra, IDA y x64dbg, y la que se usa en todo este blog. Si en algún momento ves `mov %rax,%rdi` en vez de `mov rdi, rax`, es el mismo mundo con otra notación: nada nuevo que aprender, solo orden de operandos invertido y símbolos extra.

## Siguiente paso

Con esto ya se puede seguir el post de [syscalls de Windows vs Win32 API](/tutoriales/syscalls-windows-vs-win32-api/) sin perderse en la sintaxis. El siguiente post de esta serie cubre la anatomía de un binario ELF/PE: secciones, headers y por qué el entry point casi nunca es la función `main` que escribiste.
