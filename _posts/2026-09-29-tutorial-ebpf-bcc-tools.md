---
layout: single
title: "Tutorial de eBPF: el verificador, los hooks y la caja de herramientas bcc"
date: 2026-09-29
categories: [tutoriales]
tags: [linux, kernel, ebpf, bpf, observabilidad, bcc, bpftrace, red-team, incident-response, blue-team]
excerpt: "Qué es eBPF, cómo engaña al kernel para dejarle ejecutar código seguro, y la guía completa de bcc-tools: qué hace cada herramienta y cuándo usarla."
permalink: /tutoriales/ebpf-tutorial-bcc-tools/
---

eBPF es probablemente la tecnología de kernel más importante que ha salido de Linux en la última década. Strace, tcpdump, perf, netfilter, iptables, htop — una parte del arsenal unix clásico son ventanas *indirectas* al kernel, con la latencia y el ruido que eso implica. eBPF hace algo radical: deja que **código compilado se ejecute dentro del propio kernel**, de forma segura y a velocidad nativa, cada vez que ocurre un evento determinado.

Y el mismo mecanismo que sirve para diagnosticar un servidor sirve —spoiler del siguiente post— para ocultar procesos. Este tutorial pone los cimientos: qué es, cómo funciona y para qué sirve cada herramienta de la suite bcc.

---

## 1. Qué es exactamente eBPF

BPF original (*Berkeley Packet Filter*, 1992) filtraba paquetes de red en modo usuario con un mini-VM seguro. eBPF (*extended BPF*) es el mismo concepto con esteroides: una **máquina virtual de 64 registros que vive en el kernel** y ejecuta programas que se enganchan a eventos internos del sistema.

Tres propiedades lo definen:

- **Ejecuta en el kernel**, pero sandboxed: el *verificador* garantiza que el bytecode no puede corromper memoria, colgar el kernel ni filtrar fuera de su caja de arena.
- **Se carga en caliente**: se inyecta desde userland con la syscall `bpf(2)` — sin recompilar el kernel, sin cargar módulos, sin reboot.
- **Se ata a eventos**: cada vez que se abre un fichero, se envía un paquete o se planifica un hilo, tu programa corre.

## 2. La arquitectura en una imagen mental

```text
  userspace                          kernel
  ─────────                          ──────
  programa C ──clang──> bytecode eBPF ──bpf(BPF_PROG_LOAD)──> VERIFICADOR
                                                              │ ok
                                     attach: kprobe/tracepoint/XDP/tc/LSM/uprobe
                                                              ▼
                                     JIT a código nativo, se ejecuta al dispararse el evento
                                    ◄──── MAPS (buffers) ────>  app usuario (poll/read)
```

Todo programa eBPF tiene cuatro piezas:

1. **Hooks** — dónde se dispara (ver §3).
2. **Bytecode verificado + JIT** — qué se ejecuta.
3. **Helpers** — funciones del kernel que puede llamar (`bpf_probe_read`, `bpf_printk`, `bpf_get_current_pid_tgid`...). Un programa eBPF *no puede* llamar funciones arbitrarias del kernel, solo helpers.
4. **Maps** — estructuras de datos compartidas entre kernel y userland: aquí vuelcan los datos y ahí los lee tu proceso.

## 3. Los puntos de enganche

| Hook | Se dispara... | Uso típico |
|---|---|---|
| **kprobe / kretprobe** | Al entrar/salir en cualquier función del kernel | Trazar syscalls, funciones internas |
| **tracepoint** | En puntos estables definidos por el kernel | Observabilidad con ABI garantizada |
| **fentry/fexit** | Tipo kprobe pero con tipos reales (BTF) | Programas modernos, más eficientes |
| **XDP** | Al llegar el primer byte del paquete al driver | Firewall/DDoS a velocidad line-rate |
| **tc (BPF)** | En stack de tráfico per-interface | Encaminar, reescribir, priorizar paquetes |
| **LSM (BPF LSM)** | En puntos de decisión de seguridad del kernel | Permitir/denegar accesos con lógica propia |
| **uprobe / uretprobe** | En cualquier función de un binario en userland | Trazar OpenSSL, nginx, Go runtime... |
| **cgroup v2 hooks** | Eventos del ciclo de vida de contenedores | Observabilidad/sandbox per-container |
| **socket / sockmap** | Eventos de socket, redirección entre sockets | Load-balancing en espacio de kernel |

La combinación `kprobe` + `uprobe` es la más potente para ofensiva y análisis: puedes ver *todo* lo que pasa entre un proceso y su entorno — syscalls, funciones del kernel, y llamadas a librerías compartidas.

## 4. El verificador: por qué tu programa no peta el kernel

Antes de ejecutar nada, el kernel atraviesa el bytecode con un análisis estático de todos los caminos de ejecución, que deniega cualquier programa que:

- acceda a memoria sin probar antes que el puntero es válido y el rango es seguro;
- haga bucles no acotados (los loops con límite estático llegaron en kernel 5.3);
- lea memoria del kernel sin helpers enriquecidos (`bpf_probe_read`) — *no* puede dereferenciar punteros del kernel a lo loco;
- deje referencias colgando o fugue objetos (cada referencia de mapa se limpia al terminar);
- supere el presupuesto de instrucciones de verificación (~1M instrucciones en kernels recientes; en los antiguos era 4.096 — de ahí la obsesión histórica por el *unrolling*).

Derecho de paso: necesitas `CAP_SYS_ADMIN` o, en kernels ≥ 5.8, privilegios `CAP_BPF` + `CAP_PERFMON` desglosados. Con `kernel.unprivileged_bpf_disabled=2`, userland normal no carga nada.

El precio de tanta seguridad: programas que a veces leen como C "doblado con tenacilla". Verificadores han hecho que exista todo un dialecto de C eBPF — con `volatile`, casts y trucos de bounds-check — aprendido a base de muros de `permission denied` del verificador.

## 5. Maps: la memoria del programa

| Tipo | Para qué |
|---|---|
| `BPF_MAP_TYPE_HASH` | asociación clave→valor (pids, IPs, contadores) |
| `BPF_MAP_TYPE_ARRAY` | array indexado rápido, sin lookup |
| `BPF_MAP_TYPE_LRU_*` | caches con expulsión automática |
| `BPF_MAP_TYPE_PERCPU_*` | counters sin contención entre CPUs |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` / `RINGBUF` | streams de eventos kernel → userland (el estándar hoy: ringbuf, 5.8+) |
| `BPF_MAP_TYPE_STACK_TRACE` | stacks capturados sin resolver símbolos |

El flujo canónico de una herramienta: el programa eBPF escribe un evento en un ringbuf; el proceso de userland lo consume, lo decora (símbolos, cgroups, nombres) y lo enseña. Eso es exactamente lo que hace cada herramienta de bcc-tools.

## 6. Las tres formas de escribir eBPF

| | **BCC** | **bpftrace** | **libbpf + bootstrap** |
|---|---|---|---|
| Qué es | Framework Python/C, compila en runtime | Lenguaje DSL tipo awk para tracing | Librería C + esqueleto para librar progs precompilados |
| Ideal para | Herramientas ricas, prototipos rápidos | One-liners y exploración | Herramientas de producción |
| Compila | En cada ejecución, en el host (clang) | En cada ejecución | Al compilar el proyecto (CO-RE) |
| Coste | Pesado en arranque (deps) | Pesado, pero corto | Ligero, portable, sin toolchain en el host |

**CO-RE** (*Compile Once, Run Everywhere*) merece mención aparte: con `vmlinux.h` generado del BTF del kernel y `bpf_core_read()`, un binario precompilado se adapta a distintos kernels sin recompilar. Por eso libbpf+CO-RE es el estándar actual para proyectos serios — BCC compilando en runtime tiene días contados.

## 7. Instalación y "Hola, kernel"

En Debian/Ubuntu:

```bash
sudo apt install bpfcc-tools linux-headers-$(uname -r) bpftool bpftrace
# sanity check
sudo bpftool version
ls /usr/sbin | grep bpf
```

El clásico "hola mundo": trazar cada `openat2` con el proceso y el fichero, en ~25 líneas.

```python
#!/usr/bin/env python3
# openwatch.py — traza opens en vivo
from bcc import BPF

program = r"""
#include <uapi/linux/ptrace.h>
int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char *filename)
{
    char fname[64];
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_probe_read_user_str(fname, sizeof(fname), (void *)filename);
    bpf_trace_printk("%s abre %s\n", comm, fname);
    return 0;
}
"""

b = BPF(text=program)
# trace_print() lee /sys/kernel/debug/tracing/trace_pipe
try:
    for line in b.trace_print():
        print(line)
except KeyboardInterrupt:
    pass
```

```bash
sudo python3 openwatch.py
# firefox abre /usr/share/...      ← en vivo, cada open del sistema
```

El equivalente en bpftrace, sin ficheros:

```bash
sudo bpftrace -e 'kprobe:do_sys_openat2 { printf("%s %s\n", comm, str(uptr(arg1))); }'
```

## 8. bcc-tools: para qué sirve cada una

Aquí está el dinero. El paquete `bpfcc-tools` (BCC) trae decenas de utilidades listas para usar; si sabes diagnosticar con estas, sabes lo que un eBPF real se ve en el kernel.

### Procesos y actividad de usuario

| Herramienta | Qué hace |
|---|---|
| **execsnoop** | Procesos nuevos con argumentos (incluye execs fallidos) |
| **exitsnoop** | Salidas de procesos: código de salida y vida del proceso |
| **killtrace** | Trazas de señales: qué proceso mató/sinalizó a cuál |
| **opensnoop** | Cada `open()/openat()` con el proceso que lo llamó |
| **statsnoop** | Cada `stat()` en vivo |
| **mountsnoop** | `mount()`/`umount()` en vivo |
| **syncsnoop** | `sync()`, `fsync()`, `syncfs()` en vivo |
| **bashreadline** | Lee lo que alguien escribe en *otra* sesión bash (vía uprobe en readline) |
| **ttysnoop** | Espeja la salida de una TTY (sesiones ssh post-login incluidas) |
| **pidpersec** | Procesos nuevos por segundo (churn anómalo) |

### Ficheros y sistemas de ficheros

| Herramienta | Qué hace |
|---|---|
| **filelife** | Ficheros recién creados que se borran rápido (temporales, staging de payloads) |
| **filetop** | Top de I/O por fichero/proceso (qué se está leyendo/escribiendo) |
| **fileslower** | I/O lento sobre umbral con el proceso culpable |
| **vfsstat** | Contadores de operaciones VFS por segundo |
| **vfscount** | Recuento de llamadas a funciones VFS |
| **cachestat** | Aciertos de la *page cache* en tiempo real |
| **cachetop** | Top de procesos por uso de la page cache |
| **dcsnoop / dcstat** | Rendimiento de la caché de directorios (dcache) |
| **ext4slower / xfsslower / btrfsslower / zfsslower** | Operaciones lentas sobre cada filesystem |

### Disco / block I/O

| Herramienta | Qué hace |
|---|---|
| **biolatency** | Histograma de latencia de block I/O (la métrica SRE) |
| **biosnoop** | Cada I/O de bloque con latencia y proceso emisor |
| **biotop** | Top de block I/O por proceso |
| **seeksize** | Distribución de posiciones de seek en disco |

### CPU y scheduler

| Herramienta | Qué hace |
|---|---|
| **runqlat** | Latencia en la cola del scheduler — *cuerpo* de saturación de CPU |
| **runqlen** | Longitud de la cola del scheduler en histograma |
| **runqslower** | Hilos cuya espera en cola superó un umbral |
| **offcputime** | Stacks de los hilos mientras *no* están en CPU (por qué se bloquean) |
| **offwaketime** | Igual + quién despertó al hilo (cadena de wakers) |
| **profile** | Profiler por muestreo de stacks → flamegraphs |
| **cpudist** | Distribución de tiempo en CPU por tarea |
| **cpuunclaimed** | CPU no reclamada (idle cuando había demanda latente) |
| **cpufreq** | Frecuencias de CPU muestreadas |
| **softirqs / hardirqs** | Tiempo consumido por interrupciones soft/hard |
| **syscount** | Recuento de syscalls por proceso y tipo |
| **loads** | Longitud de cola por CPU (load real, no el promedio de /proc/loadavg) |
| **pidpersec** | (también aquí) churn de procesos |

### Memoria

| Herramienta | Qué hace |
|---|---|
| **memleak** | Allocaciones sin liberar en una ventana (leaks de kmalloc/vmalloc) |
| **oomkill** | Eventos del OOM killer con stack del kernel |
| **drsnoop** | *Direct reclaim*: el kernel ya está recuperando páginas bajo presión |
| **compact** | Compaciones de memoria en curso |
| **shmsnoop** | Syscalls de memoria compartida SysV |

### Red

| Herramienta | Qué hace |
|---|---|
| **tcpconnect** | Conexiones salientes en vivo: quién conecta a dónde |
| **tcpconnlat** | Latencia de cada conexión (SYN → respuesta) |
| **tcpaccept** | Aceptaciones entrantes en vivo |
| **tcpretrans** | Retransmisiones TCP con estado del socket |
| **tcpdrop** | Segmentos descartados con el stack del kernel y la causa |
| **tcptop** | Top de throughput por host/proceso |
| **tcplife** | Resumen por conexión: duración, bytes, RTT |
| **tcptracer** | Eventos TCP con contexto de cgroup (contenedores) |
| **tcpsubnet** | Throughput agregado por subred |
| **tcpsynbl** | Backlog SYN — riesgo de drop en flood |
| **solisten** | Sockets que pasan a `listen()` en vivo |
| **gethostlatency** | Latencia de resolución DNS (uprobe sobre getaddrinfo) |
| **softnet** | Procesado de frames por CPU, drops, squeezes |

### Meta-herramientas (para construir las tuyas)

| Herramienta | Qué hace |
|---|---|
| **trace** | Kprobe ad-hoc con formato libre ("dame los arg N de función X") |
| **argdist** | Histogramas de argumentos/valores de retorno de cualquier función |
| **funccount** | Cuántas veces se llama una función (por patrón) |
| **stackcount** | Stacks de frecuencia para un evento o función |
| **funclatency** | Histograma de latencia de una función del kernel |
| **klockstat** | Contención de mutex del kernel |
| **slabratetop** | Tasa de allocación del slab en vivo |
| **deadlock_detector** | Detección de deadlocks en runtime (experimental) |

## 9. Un flujo de diagnóstico real

```bash
sudo runqlat 5          # ¿los procesos esperan mucho por CPU?
sudo runqslower 5000    # exactamente qué hilos y cuánto
sudo offcputime 15      # mientras NO corren, ¿esperan qué? (lock, IO, page fault)
sudo profile 30 > stacks.txt   # mientras SÍ corren, ¿dónde gastan tiempo?
```

Eso son cuatro comandos, cero overhead instrumentado, y una respuesta con evidencia del kernel. Es el argumento comercial de eBPF entero.

## 10. Ruta de aprendizaje

1. **bpftrace por encima de todo** — con dos sesiones de una hora ya haces análisis real. Documentación excelente (`man bpftrace`, brendan gregg's one-liners tutorial).
2. **Lee las herramientas** — el source de cada tool de bcc es ~100-200 líneas; la suite completa es un curso de eBPF disfrazado de caja de herramientas.
3. **libbpf-bootstrap** — el mejor punto de partida para eBPF "de verdad", con CO-RE.
4. *BPF Performance Tools* (Brendan Gregg) para ir a fondo.

En el siguiente post volteamos la moneda: qué pasa cuando el que carga los programas no es tu monitoring, sino un atacante. *eBPF: el rootkit que no toca el kernel*.

— Referencias: docs.kernel.org BPF · tutorial bpftrace · iovisor/bcc (tools/) · libbpf-bootstrap · "Systems Performance" y artículos de Brendan Gregg.