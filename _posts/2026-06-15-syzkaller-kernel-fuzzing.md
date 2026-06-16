---
layout: single
title: "Syzkaller — Fuzzing del Kernel de Linux"
date: 2026-06-15
categories: [tutoriales, malware]
tags: [fuzzing, kernel, syzkaller, linux, vulnerability-research, coverage-guided, syscall]
excerpt: "Qué es un fuzzer, por qué el kernel es un objetivo especialmente difícil, y cómo syzkaller lo ataca con cobertura guiada y un DSL propio para syscalls"
permalink: /tutoriales/syzkaller-kernel-fuzzing/
header:
  image: "https://upload.wikimedia.org/wikipedia/commons/7/78/Linux_5.7_kernel_panic.png"
  caption: "Linux kernel panic — Wikimedia Commons"

---

## ¿Qué es un fuzzer?

Un fuzzer es una herramienta que genera input automáticamente para un programa con el objetivo de provocar comportamientos inesperados: crashes, memory corruption, hangs, comportamientos indefinidos. La idea es sencilla: si alimentas a un programa con suficiente basura estructurada, tarde o temprano encuentras un bug que un auditor humano nunca habría buscado ahí.

Hay tres grandes familias:

| Tipo | Cómo funciona | Ejemplo |
|---|---|---|
| **Blackbox** | Genera input completamente aleatorio o con plantillas fijas | Peach Fuzzer |
| **Greybox** | Usa feedback de ejecución (cobertura) para mutar input | AFL, libFuzzer, honggfuzz |
| **Whitebox** | Análisis estático / simbólico para explorar todas las ramas | KLEE, angr |

El greybox con cobertura guiada (**coverage-guided fuzzing**) es el que domina hoy. La mecánica es:

1. Toma un corpus inicial de inputs.
2. Ejecuta el target e instrumentaliza qué bloques básicos se visitan.
3. Si un input nuevo toca ramas no vistas antes → lo guarda en el corpus.
4. Muta ese input y repite.

Con esto el fuzzer *aprende* a profundizar en el código en lugar de tirar dardos al azar. AFL y libFuzzer han encontrado miles de CVEs en parsers, codecs y librerías de red usando exactamente este principio.

---

## El kernel es un caso especial

Fuzzear una librería en userspace es relativamente simple: instrumentas la librería, le das inputs, recoges crashes con AddressSanitizer. El kernel plantea problemas distintos:

- **La interfaz no es un fichero ni stdin**, son **syscalls**. Cada syscall tiene semántica, tipos y restricciones propias. Llamar a `write()` con un fd inválido no es interesante; llamar a `write()` sobre un fd que abriste con `open()` sobre un filesystem montado *sí* puede llegar a código que nadie ha auditado.
- **Las syscalls tienen dependencias entre sí**. Para llegar al código de red del kernel necesitas: crear un socket, configurarlo, puede que hacer bind, puede que conectar... Una secuencia de syscalls con argumentos coherentes, no una syscall aislada.
- **Un crash no es solo un segfault manejable** — el kernel muere y llevate toda la VM o máquina contigo.
- **El estado persiste** entre llamadas. El kernel mantiene estado (procesos, ficheros abiertos, conexiones) que afecta a cómo procesa las siguientes syscalls.

Un fuzzer genérico como AFL no entiende nada de esto. Necesitas algo que *hable el idioma del kernel*.

---

## Syzkaller

[Syzkaller](https://github.com/google/syzkaller) es el fuzzer de kernel desarrollado por Google, mantenido activamente y responsable de miles de bugs en Linux, Android, FreeBSD y otros kernels. Es coverage-guided y está diseñado específicamente para fuzzear la capa de syscalls.

### Arquitectura

```text
┌─────────────────────────────┐
│         syz-manager         │  ← orquesta todo, recoge crashes
│  (corre en la máquina host) │
└──────────────┬──────────────┘
               │ SSH / RPC
    ┌──────────▼──────────┐
    │    VM (QEMU/KVM)    │
    │  ┌───────────────┐  │
    │  │  syz-fuzzer   │  │  ← genera programas, muta corpus
    │  └──────┬────────┘  │
    │         │ fork      │
    │  ┌──────▼────────┐  │
    │  │  syz-executor │  │  ← ejecuta las syscalls reales
    │  └───────────────┘  │
    └─────────────────────┘
```

- **syz-manager**: corre en el host, gestiona las VMs, recibe cobertura y crashes, los deduplica y reporta.
- **syz-fuzzer**: corre dentro de la VM, mantiene el corpus, genera y muta *programas* (secuencias de syscalls), solicita ejecución.
- **syz-executor**: proceso mínimo en C que recibe un programa serializado y lo ejecuta con las syscalls reales. Diseñado para ser lo más fino posible — nada de overhead.

### syzlang — el DSL de syscalls

El problema de describir syscalls tiene su propia solución en syzkaller: **syzlang**, un lenguaje de descripción de syscalls. En lugar de que el fuzzer genere bytes aleatorios, genera *argumentos tipados y coherentes*.

Ejemplo de cómo syzlang describe `socket()`:

```text
socket(domain flags[socket_domain], type flags[socket_type], proto int32) fd[sock]

socket_domain = AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, ...
socket_type   = SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET, ...
```

Y una llamada dependiente:

```text
bind(fd fd[sock], addr ptr[in, sockaddr], addrlen len[addr])
```

Syzkaller sabe que el `fd` que devuelve `socket()` puede pasarse a `bind()`. Así construye secuencias coherentes como:

```c
r0 = socket(AF_INET6, SOCK_RAW, 0)
bind(r0, &(0x7f0000000000)={AF_INET6, 0, 0, @loopback}, 0x1c)
setsockopt(r0, SOL_IPV6, IPV6_RECVPKTINFO, &(0x7f0000000040)=0x1, 0x4)
sendmsg(r0, ...)
```

Esto es lo que diferencia a syzkaller de un fuzzer genérico: entiende la semántica de las syscalls y genera programas que *tienen sentido* desde el punto de vista del kernel.

### Cobertura con KCOV

Para que el fuzzer guiado por cobertura funcione en el kernel, necesitas instrumentación. Syzkaller usa **KCOV** (`CONFIG_KCOV=y`), un mecanismo del kernel Linux que expone la cobertura de bloques básicos a userspace a través de `/sys/kernel/debug/kcov`.

El executor activa KCOV antes de ejecutar cada programa, lee qué PCs se ejecutaron y se los reporta al fuzzer. Si un programa nuevo toca PCs no vistas antes, entra al corpus.

### Detección de bugs con sanitizers

Un crash de kernel solo lo detectas si el kernel *dice* que crasheó. Syzkaller se apoya en:

- **KASAN** (`CONFIG_KASAN=y`) — detecta use-after-free, out-of-bounds en heap y stack.
- **UBSAN** (`CONFIG_UBSAN=y`) — detecta undefined behavior (overflow de enteros, shifts inválidos...).
- **KMSAN** (`CONFIG_KMSAN=y`) — detecta usos de memoria no inicializada.
- **LOCKDEP** — detecta deadlocks y violaciones del orden de bloqueos.

El kernel configurado para fuzzing tiene estos sanitizers activos y reporta violaciones vía el mecanismo de `panic` / `BUG()`. El syz-manager recoge esos splats del log serial de la VM y los clasifica.

### Setup mínimo

Necesitas:

```bash
# 1. Kernel con las opciones de fuzzing
CONFIG_KCOV=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_DEBUG_INFO=y
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y

# 2. Imagen de VM (Debian minimal funciona bien)
# syzkaller tiene scripts para crearla:
./tools/create-image.sh

# 3. Compilar syzkaller
make all

# 4. Configurar syz-manager
cat > my.cfg << 'EOF'
{
  "target": "linux/amd64",
  "http": "127.0.0.1:56741",
  "workdir": "./workdir",
  "kernel_obj": "/path/to/linux",
  "image": "./stretch.img",
  "sshkey": "./stretch.id_rsa",
  "syzkaller": ".",
  "procs": 8,
  "type": "qemu",
  "vm": {
    "count": 4,
    "kernel": "/path/to/linux/arch/x86/boot/bzImage",
    "cpu": 2,
    "mem": 2048
  }
}
EOF

./bin/syz-manager -config my.cfg
```

La UI web en `localhost:56741` muestra el corpus, la cobertura y los crashes en tiempo real.

---

## Qué ha encontrado syzkaller

Syzkaller tiene un bot continuo llamado **syzbot** (`syzkaller.appspot.com`) que fuzzea el kernel mainline de forma permanente y reporta bugs directamente a la lista LKML. Algunos ejemplos del impacto real:

- Bugs en la pila de red IPv6, Netlink, BPF
- Use-after-free en el subsistema de ficheros (ext4, btrfs, NFS)
- Bugs en drivers USB (usando emulación de dispositivos USB)
- Cientos de CVEs en Android kernel

La idea de usar un DSL tipado para syscalls ha demostrado ser el enfoque correcto: el fuzzer explora código que nunca alcanzaría con input aleatorio porque las precondiciones son demasiado específicas.

---

## Referencias

- [Repositorio oficial syzkaller](https://github.com/google/syzkaller)
- [syzbot — bugs activos en el kernel](https://syzkaller.appspot.com)
- [Documentación: cómo escribir descripciones syzlang](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md)
- [KCOV: kernel coverage para fuzzing](https://www.kernel.org/doc/html/latest/dev-tools/kcov.html)
