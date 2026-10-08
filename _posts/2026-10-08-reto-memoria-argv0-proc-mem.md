---
layout: single
title: "Reto de memoria: la flag viva en argv[0] — munmap, pause y /proc/pid/mem"
date: 2026-10-08
categories: [ctf]
tags: [ctf, forense, memoria, linux, procfs, munmap, gdb, euskalhack]
excerpt: "Reto mínimo de forense de memoria rescatado del cajón de EuskalHack 2025: munmap sobre la página de argv[0], fgets y pause. Verificado en vivo en Debian 13: el original acaba en SIGSEGV y la técnica real — leer la memoria de un proceso pausado vía /proc/pid/mem — funciona, con la trampa de ptrace_scope incluida."
permalink: /ctf/reto-memoria-argv0/
---

Sigo vaciando el cajón de la edición pasada de EuskalHack (junio 2025): entre las cosas que nunca llegaron al blog estaba este reto diminuto de forense de memoria. Igual que en la serie de [Protostar]({{ "" | absolute_url }}/tutoriales/protostar-endian-gdb/), nada reescrito de guías: lo que sigue lleva las **salidas reales** de ejecutarlo hoy en mi Debian 13 (kernel 6.12).

## El reto completo

```c
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int _, char** argv)
{
    FILE* f;
    munmap((void*) ((long)argv[0] & ~0xfff), 1);

    if(f = fopen("flag", "rb"))
    {
        fgets(argv[0], 32, f);
        fclose(f);
    }
    pause();
}
```

Quince líneas que esconden tres conceptos: desmapear memoria propia por código, la geometría del stack al nacer un proceso, y la técnica de **pausar un proceso y leer su memoria viva**.

## Qué hace cada línea

- `munmap((void*) ((long)argv[0] & ~0xfff), 1)` — alinea la dirección de `argv[0]` a la página y desmapea **una página entera** (el `1` se redondea al alza a 4096 bytes). Esa página es la **cima del stack**: la zona donde el kernel dejó los strings de `argv` y `environ` al arrancar el proceso.
- `fopen("flag", "rb")` — ruta **relativa al cwd**: si no hay `flag` en el directorio, todo el bloque del `if` se salta.
- `fgets(argv[0], 32, f)` — escribe directamente **sobre el puntero argv[0]**: la flag aterriza en la zona de argv del stack, sobrescribiendo el nombre del binario.
- `pause()` — el proceso queda dormido para siempre con la flag viva en su memoria. Ahí está el juego: sin salir del proceso, sacar la flag leyendo su memoria.

## Ejecutado hoy: SIGSEGV

```console
$ printf 'FLAGTEST{argv0_survive}\n' > flag && gcc reto-memoria.c -o reto
$ ./reto
Violación de segmento            # exit = 139
```

Con la `flag` presente, el original **muere al instante**. El porqué es geometría de VMA:

1. Los strings de `argv`/`environ` viven en las **páginas altas del stack** (el kernel los deja allí al crear el proceso).
2. El `munmap` convierte la página que contiene a `argv[0]` en un **agujero**: la VMA del stack se queda sin su parte alta.
3. La VMA del stack en x86-64 es `VM_GROWSDOWN`: por diseño **solo se expande hacia abajo** (y por debajo de lo que ya está mapeado). No hay camino de vuelta hacia arriba.
4. `fgets` intenta escribir sobre el agujero → fault sin VMA que lo reclame → **SIGSEGV**. Ni un byte de la flag llegó a memoria.

Es decir: tal cual está escrito, el reto es una autodestrucción pedagógica. O el ponente lo usaba para enseñar esto mismo, o corría sobre particularidades que los apuntes no recogen; lo que sí puedo afirmar es lo que hace hoy en un kernel moderno — y **por qué**.

## La técnica que sí enseña: pausar y leer

Modificando tres líneas (quitando el `munmap`) el flujo funciona: el proceso queda **pausado con la flag viva en `argv[0]`**:

```c
int main(int _v, char** argv){
    FILE* f;
    if((f = fopen("flag","rb"))){ fgets(argv[0],32,f); fclose(f); }
    pause();
}
```

Y ahora la parte buena — leer su memoria **sin tocar el proceso**:

```python
import subprocess, time, re
p = subprocess.Popen(['./reto_pause'])
time.sleep(0.4)                                  # da tiempo al fgets + pause()
maps = open(f'/proc/{p.pid}/maps').read()        # 1. localizar el VMA del stack
m = re.search(r'^([0-9a-f]+)-([0-9a-f]+) .*\[stack\]$', maps, re.M)
end = int(m.group(2), 16)
with open(f'/proc/{p.pid}/mem','rb') as fd:      # 2. leer las páginas altas
    fd.seek(end - 3*4096)
    data = fd.read(3*4096)
```

Salida **real** de mi prueba:

```console
vivo tras escritura: True (pid 1190458)
linea maps: 7ffd259d8000-7ffd259f9000 rw-p 00000000 00:00 0
== vivo en la memoria del proceso pausado ==
   'FLAGTEST{argv0_survive}'
   './reto_pause'
```

La flag está **viva en las últimas páginas del `[stack]`** del proceso pausado, junto al string original de `argv[0]` que nunca fue machacado del todo. Ese es el patrón que el reto quería demostrar: el paquete `maps → seek → read` de `/proc`.

## La trampa que muerde: ptrace_scope

Abrir `/proc/pid/mem` no es gratis: el procfs hace un control `ptrace_may_access` en el `open`. Con la configuración por defecto de Debian (`kernel.yama.ptrace_scope = 1`), **solo un ancestro directo** del proceso puede hacerlo: el shell que lo lanzó puede; un proceso ajeno (o incluso un hijo de otra sesión) recibe `EPERM`.

Para el forense "de verdad" hay caminos elegantes:

```console
$ gdb -q ./reto_pause -ex run        # attach como padre/ancestro
# ... en pause(): ^C → x/s argv[0] ... o directamente:
$ gcore 1190458                      # volcar el core completo del proceso vivo
$ strings 1190458.core | grep -i flag
```

`gcore` (gdb-core) es la vía limpia: te lleva el proceso entero pausado a un fichero para analizarlo con calma.

## Lo que enseñan quince líneas

- Cualquier página de tu proceso — **incluso las de tus propios argv** — es desmapeable. Y Linux no repone los agujeros del stack hacia arriba.
- La lectura de memoria de otro proceso es un problema de **geometría** (`maps` te da los límites) y de **permiso** (`yama` decide quién puede). Saber las dos caras es lo que separa a un lector de un analista.
- `pause()` + `/proc/pid/mem` + `gcore` = el kit básico de forense de procesos vivos — el mismo músculo que luego usas para volcar credenciales en memoria o cazar flag en memoria.

Sigo con más material crudo de la edición en el cajón (apuntes de una charla sobre el stealer Lumma, entre otros); veremos si se convierten en post o quedan para el siguiente.