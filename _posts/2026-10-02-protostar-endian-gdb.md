---
layout: single
title: "Protostar: big endian vs little endian y cómo mirar la pila con el examine de gdb"
date: 2026-10-02
categories: [tutoriales]
tags: [protostar, gdb, endian, memoria, pwn, explotacion, apuntes, x86]
excerpt: "Apuntes del CTF Protostar: qué es big endian vs little endian visto en vivo con los dumps de gdb (x/64xb vs x/64xw sobre stack0) y referencia completa del comando x (examine)."
permalink: /tutoriales/protostar-endian-gdb/
---

Empiezo una serie de apuntes sobre **Protostar** (las *Exploit Exercises* clasificas de Exploit Education: `stack0` a `stack7`, format strings, heap...). Nada de guía oficial reescrita: apuntes con dumps **reales de la sesión**, que es lo que al final hace que la memoria del stack deje de ser una sopa de números.

La primera pieza conceptual que hay que tener clara antes de escribir un solo payload: **el orden de los bytes** (endianness), y saber *mirar* memoria con gdb. Si no ves lo que tienes delante, no puedes explotarlo.

## Punto de partida: stack0 en gdb

```console
(gdb) run
Starting program: /opt/protostar/bin/stack0
Breakpoint 1, main (argc=1, argv=0xbffffd64) at stack0/stack0.c:10
10  stack0/stack0.c: No such file or directory.
    in stack0/stack0.c
```

La línea `No such file or directory` no es un error tuyo: el binario lleva los paths de DWARF de la máquina donde se compiló. Ignora (o arregla con `set substitute-path`) — el debug símbolos funcionan igual.

El valor a recordar a partir de ahora: **`argv = 0xbffffd64`**. gdb acaba de chivarnos una dirección de la pila; más adelante la volveremos a ver... *cambiada de sitio por el endianness*.

## Dos vistas del mismo trozo de pila

Quiero ver la memoria en `$esp` (el tope de pila). Primero **byte a byte**:

```console
(gdb) x/64xb $esp
0xbffffc50:	0x00	0x00	0x00	0x00	0x01	0x00	0x00	0x00
0xbffffc58:	0xf8	0xf8	0xff	0xb7	0x6e	0x18	0xf0	0xb7
0xbffffc60:	0xf4	0x7f	0xfd	0xb7	0x65	0x61	0xec	0xb7
0xbffffc68:	0x78	0xfc	0xff	0xbf	0x75	0xda	0xea	0xb7
0xbffffc70:	0xf4	0x7f	0xfd	0xb7	0x20	0x96	0x04	0x08
0xbffffc78:	0x88	0xfc	0xff	0xbf	0xe8	0x82	0x04	0x08
0xbffffc80:	0x40	0x10	0xff	0xb7	0x20	0x96	0x04	0x08
0xbffffc88:	0xb8	0xfc	0xff	0xbf	0x69	0x84	0x04	0x08
```

Y ahora la **misma memoria, de 4 en 4 bytes** (words):

```console
(gdb) x/64xw $esp
0xbffffc50:	0x00000000	0x00000001	0xb7fff8f8	0xb7f0186e
0xbffffc60:	0xb7fd7ff4	0xb7ec6165	0xbffffc78	0xb7eada75
0xbffffc70:	0xb7fd7ff4	0x08049620	0xbffffc88	0x080482e8
0xbffffc80:	0xb7ff1040	0x08049620	0xbffffcb8	0x08048469
0xbffffc90:	0xb7fd8304	0xb7fd7ff4	0x08048450	0xbffffcb8
0xbffffca0:	0xb7ec6165	0xb7ff1040	0x0804845b	0xb7fd7ff4
0xbffffcb0:	0x08048450	0x00000000	0xbffffd38	0xb7eadc76
0xbffffcc0:	0x00000001	0xbffffd64	0xbffffd6c	0xb7fe1848
0xbffffcd0:	0xbffffd20	0xffffffff	0xb7ffeff4	0x0804824b
0xbffffce0:	0x00000001	0xbffffd20	0xb7ff0626	0xb7fffab0
0xbffffcf0:	0xb7fe1b28	0xb7fd7ff4	0x00000000	0x00000000
0xbffffd00:	0xbffffd38	0x201cae9c	0x0a5d588c	0x00000000
0xbffffd10:	0x00000000	0x00000000	0x00000001	0x08048340
0xbffffd20:	0x00000000	0xb7ff6210	0xb7eadb9b	0xb7ffeff4
0xbffffd30:	0x00000001	0x08048340	0x00000000	0x08048361
0xbffffd40:	0x080483f4	0x00000001	0xbffffd64	0x08048450
```

Son **los mismos 256 bytes** (64×4). Fíjate en las direcciones que repiten patrón:

| En la vista `xw` (word) | En la vista `xb` (bytes) |
|---|---|
| `0x08049620` | `20 96 04 08` |
| `0x080482e8` | `e8 82 04 08` |
| `0xb7eada75` | `75 da ea b7` |
| `0xbffffcb8` | `b8 fc ff bf` |

## Little endian: los bytes van al revés

Ese patrón no es un accidente — es **little endian**: las máquinas x86/x64 y la mayoría de ARM guardan las palabras con el **byte menos significativo primero**. La dirección `0x08049620` vive en memoria como `20 96 04 08`: *se escribe al revés*, como el decimal que se lee de derecha a izquierda.

Tabla de referencia mental con el clásico `0x12345678`:

| Endianness | Orden en memoria |
|---|---|
| **Little endian** (x86, x64, ARM LE) | `78 56 34 12` |
| **Big endian** (motores viejos, SPARC; *network byte order* de los protocolos) | `12 34 56 78` |

Tres notas útiles para la práctica:

- **En protostar vas a ver `08` el último byte de casi todo** — es el final de las direcciones del segmento de código (0x08...). Cuando en la `xb` ves un byte terminal `08`, probablemente acabas de mirar el final (LE) de una dirección `.text`.
- **Cuando escribas payloads de overflow, escribes en el orden humano pero el CPU lee little-endian**: para poner la dirección `0x08049620` en la pila, tu input necesita los bytes `\x20\x96\x04\x08`. Este orden invertido es el error clásico del día 1.
- **Network byte order = big endian**: `htons()`/`htonl()` existen porque los protocolos de red pactan BE y tu host LE los traduce.

¿Y el `argv = 0xbffffd64` del breakpoint? Ya está en los dumps: mira la fila de `0xbffffcc0`/`0xbffffd40` en la vista `xw` — ahí está el `0xbffffd64` *derecho*, porque la vista word ya agrupa los bytes en little-endian por ti. La memoria cruda del `xb` lo enseñaría partido (`64 fd ff bf`).

## El comando `x` (examine): `x/NFU dirección`

```text
x/NFU dirección   →   examina la memoria
```

- **N** = cuántas *unidades* mostrar (¡no son bytes! 16 unidades `w` = 64 bytes)
- **F** = formato de salida
- **U** = tamaño de la unidad

| U | Tamaño |
|---|---|
| `b` | byte (1) |
| `h` | halfword (2) |
| `w` | word (4) |
| `g` | giant (8) |

| F | Muestra |
|---|---|
| `x` | hexadecimal |
| `d` | decimal con signo |
| `u` | decimal sin signo |
| `t` | binario (two) |
| `o` | octal |
| `c` | carácter |
| `s` | string |
| `i` | instrucción (desensambla) |

Recetas del día a día:

```console
(gdb) x/64xb $esp        # 64 bytes crudos de la pila
(gdb) x/64xw $esp        # los mismos bytes, como words/direcciones legibles
(gdb) x/16xg $esp        # de 8 en 8 (punteros de 64-bit)
(gdb) x/4i $eip          # las próximas 4 instrucciones que ejecutarás
(gdb) x/s $esp           # leer como string (útil para buffers con input)
(gdb) x/x $ebp           # un solo valor, hex
(gdb) x/32xc $ecx        # chars con su código
```

Detalles que se aprenden a golpe de sesión:

- `x/64xb` y `x/16xw` miran **el mismo rango** (64 y 64 bytes). La N siempre son unidades.
- `$esp`/`$eip`/`$ebp` son registros; en x86_64 el stack pointer es `$rsp`. También valen direcciones literales: `x/24xw 0xbffffc50`.
- Para examinar **variables** con symbolos mejor `p` (`p/x modified`, `p &modified`); `x` es para memoria en general.
- `x` re-lee la dirección *sin avanzar* (a diferencia de `display` que refresca cada stop); `x/4i $eip` no avanza el PC: se puede llamar una y otra vez.

## Lo que viene (y por qué esto importa)

En `stack0` el objetivo es clásico: un `gets()` en un `char buffer[64]` y una variable `modified` justo después, que hay que voltear de `0` a distinto de cero. El overflow lo hace fácil; el endianness y leer la pila con `x` es lo que te dice **dónde y en qué orden** escribiste. En el siguiente apunte: el overflow en sí, con `info frame` y la distancia exacta de la pila.

Apuntes → *Exploit Education / Protostar* · sesión con gdb en el ISO