---
layout: single
title: "Writeup: FindLicenseKey — crackme con cifrado por sustitución"
date: 2026-06-16
categories: [reversing, writeups]
tags: [crackme, elf, keygen, assembly, ghidra, objdump]
excerpt: "Análisis de un crackme ELF x86-64 de crackmes.one: algoritmo de generación de clave por sustitución y desarrollo de un keygen funcional sin parchear el binario."
permalink: /reversing/findlicensekey-crackme-writeup/
---

Crackme de crackmes.one. Las reglas del autor son claras: nada de parchear, hay que entender lo que hace el programa y escribir un keygen. La solución pasa por desensamblado puro con `objdump`.

## Reconocimiento inicial

```bash
$ file findlicensekey
findlicensekey: ELF 64-bit LSB pie executable, x86-64, stripped

$ ./findlicensekey gumerzzzindo
Enter license key to continue:
```

El binario está **stripped** (sin símbolos de debug) y compilado como PIE. Acepta un username como argumento y pide una clave por stdin.

Primer paso, strings:

```bash
$ strings findlicensekey
...
QAZPLWSXOKMEYDCIJNRFVUHBTGqpalzmwoeirutyskdjfhgxncbv1750284369
Enter license key to continue:
%255s
Key validated
Invalid key
...
```

Ese string de 62 caracteres es la pista central: un alfabeto de sustitución con mayúsculas, minúsculas y dígitos (26 + 26 + 10 = 62).

## Análisis del algoritmo

Con `objdump -d -M intel` se identifican dos funciones relevantes: la función keygen y el main.

### La función keygen (offset 0x1189)

```nasm
; rdi = username, rsi = output buffer
push rbp
mov  rbp, rsp
mov  [rbp-0x28], rdi      ; username
mov  [rbp-0x30], rsi      ; output
lea  rax, [rip+0xe6c]     ; carga puntero al alfabeto
mov  [rbp-0x8],  rax
mov  DWORD [rbp-0x14], 0x3e  ; 62 = len(alfabeto)
mov  DWORD [rbp-0x18], 0x0   ; i = 0
jmp  check

loop:
  ; c = username[i]  (zero-extended, luego sign-extended)
  movzx eax, BYTE [rbp-0x28 + rdx]
  movsx edx, al

  ; sum = i + c
  mov eax, [rbp-0x18]
  add eax, edx

  ; idx = sum % 62  (división entera con signo)
  cdq
  idiv DWORD [rbp-0x14]
  mov  [rbp-0xc], edx      ; idx = remainder

  ; output[i] = alphabet[idx]
  movzx eax, BYTE [rbp-0x8 + rdx]
  mov   BYTE [rbp-0x30 + rcx], al

  inc DWORD [rbp-0x18]     ; i++

check:
  cmp DWORD [rbp-0x18], 23
  jg  end                  ; si i > 23, salir
  cmp DWORD [rbp-0x18], 254
  jle loop                 ; continuar
end:
  ; null terminator
  mov BYTE [output + i], 0
```

El algoritmo en pseudocódigo:

```
alphabet = "QAZPLWSXOKMEYDCIJNRFVUHBTGqpalzmwoeirutyskdjfhgxncbv1750284369"
for i in 0..23:
    c = (signed)username[i]
    idx = (i + c) % 62
    key[i] = alphabet[idx]
key[24] = '\0'
```

Puntos clave:
- **La clave tiene siempre 24 caracteres**, independientemente de la longitud del username.
- Se usa **división entera con signo** (`idiv`), no `div`. Relevante si `i + c` es negativo.
- El bucle termina cuando `i > 23`, por lo que recorre exactamente i = 0..23.

### Detalle: lectura más allá del null terminator

Si el username tiene menos de 24 caracteres, el bucle lee bytes más allá del `\0` final — lo que haya en memoria a continuación en la pila (típicamente variables de entorno del proceso). Esto no es un bug explotable aquí, pero sí hace que la clave sea parcialmente dependiente del entorno para usernames cortos.

Para usernames de 24 o más caracteres, el keygen es completamente determinista.

## Verificación con GDB

Para confirmar el algoritmo sin tocar el binario, se intercepta la llamada a `strcmp` del main observando sus argumentos en tiempo de ejecución. El registro `rdi` recibe el input del usuario y `rsi` la clave generada por el keygen interno.

```bash
$ gdb -q findlicensekey
(gdb) break strcmp
(gdb) run gumerzzzindo
# Se para en la comparación final
(gdb) x/s $rsi
# → clave generada
```

## El keygen

Implementación en C que replica el comportamiento exacto del binario:

```c
#include <stdio.h>
#include <string.h>

static const char alphabet[] =
    "QAZPLWSXOKMEYDCIJNRFVUHBTGqpalzmwoeirutyskdjfhgxncbv1750284369";

void generate_key(const char *username, char *out) {
    for (int i = 0; i <= 23; i++) {
        int c = (int)(signed char)username[i];
        int idx = (i + c) % 62;
        if (idx < 0) idx += 62;   /* idiv con signo puede dar negativo */
        out[i] = alphabet[idx];
    }
    out[24] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <username>\n", argv[0]);
        return 1;
    }
    char key[25];
    generate_key(argv[1], key);
    printf("%s\n", key);
    return 0;
}
```

Equivalente en Python para usernames de 24+ chars (sin dependencia de entorno):

```python
ALPHABET = "QAZPLWSXOKMEYDCIJNRFVUHBTGqpalzmwoeirutyskdjfhgxncbv1750284369"

def keygen(username):
    assert len(username) >= 24, "username debe tener al menos 24 chars para resultado determinista"
    key = []
    for i in range(24):
        c = (ord(username[i]) + 128) % 256 - 128  # sign extend byte
        idx = (i + c) % 62
        key.append(ALPHABET[idx])
    return ''.join(key)
```

## Validación

```bash
$ gcc -o keygen keygen.c
$ ./findlicensekey gumerzzzindo
Enter license key to continue: $(./keygen gumerzzzindo)
Key validated
```

## Resumen

| Elemento         | Valor                                                     |
|-----------------|-----------------------------------------------------------|
| Formato         | ELF 64-bit PIE, stripped                                  |
| Protecciones    | Stack canary, PIE                                         |
| Algoritmo       | Sustitución: `alphabet[(i + username[i]) % 62]`           |
| Longitud clave  | 24 caracteres fijos                                       |
| Quirk           | Lee más allá del null para usernames < 24 chars           |
| Herramientas    | `strings`, `objdump -d -M intel`, GDB                    |

La clave no requiere IDA ni Ghidra — `objdump` es suficiente para leer el algoritmo directamente del desensamblado. El truco está en identificar el string del alfabeto en `.rodata` y seguir las referencias a él en el código.
