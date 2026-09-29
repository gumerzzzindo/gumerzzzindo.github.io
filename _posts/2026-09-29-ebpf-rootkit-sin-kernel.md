---
layout: single
title: "eBPF: el rootkit que no toca el kernel"
date: 2026-09-29
categories: [tutoriales, analisis]
tags: [linux, kernel, ebpf, red-team, malware-analysis, incident-response, rootkit, persistence, blue-team, lkm]
excerpt: "Los rootkits clásicos cargan módulos y parchean syscalls. Los modernos cargan bytecode verificado mediante bpf() y el kernel se lo consiente. Cómo funcionan los rootkits basados en eBPF y cómo detectarlos."
permalink: /tutoriales/ebpf-rootkit-sin-kernel/
---

Para instalar un rootkit clásico en Linux hacías `insmod`. El kernel carga tu módulo, tu módulo parchea la syscall table o sustituye el handler de `/proc`, y a partir de ahí el sistema miente a quien pregunta. El problema del atacante: cada paso deja rastro — `/proc/modules`, logs de `insmod`, firmas de módulos obligatorias (`CONFIG_MODULE_SIG_FORCE`), `lsmod` como primer comando de cualquier triaje.

eBPF ofrece el mismo acceso al flujo del kernel… con la bendición del propio kernel. Nada que parchear, todo en memoria, invisble para `lsmod`, sandbox oficial del kernel. Este post analiza cómo funciona un rootkit basado en eBPF —con técnicas reales de TripleCross, bad-bpf y ebpfkit— y, sobre todo, cómo se detecta el juego.

*(Pre-requisito: echa un ojo al anterior — [tutorial de eBPF y bcc-tools](/tutoriales/ebpf-tutorial-bcc-tools/) — para tener el vocabulario a mano.)*

---

## 1. Dos aclaraciones para empezar

**BPFdoor no usa BPF.** Apareció bautizado como "BPFdoor" en análisis de incident-response y mucha gente lo asoció con eBPF. Es un backdoor que usa raw sockets con paquetes falsos TCP/RST/SYN como mecanismo de knock. El nombre es pura coincidencia de siglas. Myth desmontado.

**Un rootkit eBPF no es un exploit de kernel.** eBPF está sandboxed por diseño: un programa verificado *no puede* escribir memoria del kernel, parchear la syscall table ni escalar privilegios. Eso que sigue no rompe el sandbox — lo explota desde dentro, con las APIs que el kernel ofrece a propósito para *modificar* el comportamiento visible del sistema.

## 2. Por qué eBPF es un jackpot

| | **LKM clásico** | **Rootkit eBPF** |
|---|---|---|
| Carga | `finit_module()` → insmod | `bpf(2)` desde userspace |
| Firmas / lockdown | Firmas obligatorias, `lockdown` | Sin firmas; el verificador *prefiere* bytecode "limpio" |
| Visibilidad | `/proc/modules`, lsmod | Nada equivalente; `bpftool` es opcional y no está en todo host |
| En disco | `.ko` con strings | Nada: bytecode en memoria, opcionalmente *pinned* en `bpffs` |
| Escritura kernel | Sí (parchea lo que quiere) | No (por diseño) — pero no la necesita (ver §3) |
| Supervivencia a reboot | Hay que reinstalar | Idem; se recarga con el daemon que lo vuelve a pinchar |
| Detección de carga | auditd de módulos, syslog de insmod | auditd de syscall `bpf()` (poca gente lo configura) |

La diferencia clave: **el rootkit LKM se camufla después de actuar. El rootkit eBPF está protegido por las mismas garantías de seguridad que hace al kernel aceptarlo** — al kernel le resulta natural que ese código esté ahí.

## 3. La navaja suiza: `bpf_probe_write_user()`

Dentro del sandbox, el helper más interesante para un atacante es este:

```c
long bpf_probe_write_user(void *dst, const void *src, u32 len);
```

Escribe en **memoria de usuario** desde un programa eBPF. A primera vista no parece gran cosa; al fin y al cabo solo puede tocar memoria de proceso, no kernel. El truco está en *cuándo* corre el programa: mientras una syscall **está a mitad de camino hacia userland**, el buffer de destino *ya es memoria de usuario*.

El kernel copia los datos por *value* hacia userland con `copy_to_user()`. Si tu hook eBPF corre en el instante justo entre "el kernel ha preparado el resultado" y "el proceso userland lo ha leído", puedes **reescribir el contenido de datos que el kernel va a entregar**. No has tocado el kernel: has tocado *lo que el kernel te dice*.

## 4. Ocultar procesos: el hook de `getdents64()`

Cuando `ls` o `readdir()` enumeran un directorio, el buffer que recibe el proceso con resultados viene de `getdents64()`. Un hook kprobe/kretprobe sobre esa función, con `bpf_probe_write_user()`, puede reescribir entradas de ese buffer:

```c
// Esquema simplificado (ver repos bad-bpf / TripleCross para el real)
SEC("ksyscall/getdents64")
int BPF_KSYSCALL(hide_dirent, int fd, void *dirent, unsigned int count)
{
    // 1. recorre las entradas linux_dirent64 del buffer del usuario
    //    (solo lectura con bpf_probe_read_user)
    // 2. si d_name coincide con el objetivo (p. ej. el pid del malware)
    // 3. bpf_probe_write_user() le machaca d_ino, d_reclen y el nombre con \x00
    return 0;
}
```

El resultado: `ls` no muestra el proceso porque `/proc/<pid>` ya no aparece en la enumeración — pero el proceso existe, los archivos existen, y el kernel sigue creyendo que los ha listado bien. La mentira la comete el propio `ls` leyendo datos envenenados — como ocurre siempre en el MITM sobre `copy_to_user`.

El mismo truco aplica a `proc_pid_readdir()` para ocultar PIDs en `ps`, y a los lectores de `/proc/net/*` (ver §5).

## 5. Ocultar puertos y conexiones

Dos caminos:

**a) Hook de seq_file** (`tcp4_seq_show` y amigos) — cuando haces `cat /proc/net/tcp`, el kernel llama a la función `show()` que va imprimiendo líneas en el buffer. El hook intercepta y, con `bpf_probe_write_user`, sobreescribe con `\x00` la entrada de la conexión a ocultar. `netstat` y `ss` no ven el puerto.

**b) No tocar proc: controlar la red con tc/XDP.** Un programa **tc BPF** se engancha a la tarjeta de red y procesa paquetes reales, con permiso *legítimo* para reescribirlos. Ahí la puerta es mayor:

- **Backdoor por paquete**: reescribe el destino de un paquete que cumple un patrón (magic payload, destino concreto) para mandarlo a un shell en local, a un puerto distinto, o por un tunnel. El C2 no aparece en ningún log porque el paquete "legítimo" sigue su curso.
- **MITM total**: TripleCross lo demostró — reescribir TCP a la carta para inyectar comandos, capturar credenciales y hacer exfiltración sobre el propio tráfico de la víctima.
- **Anti-forense en la red**: el hook también puede ocultar paquetes de las herramientas de monitorización del propio host.

## 6. Keylogging e infostealing con uprobes

Los **uprobes** enganchan funciones de librerías en userland. Ejemplo real: una sesion SSH en marcha llama a `read()` de libreadline; con un uprobe+uretprobe sobre readline capturas TODO lo que el usuario teclea en esa shell — passwords incluidos — y lo envías a un daemon de userland vía ringbuf o mapa perf.

```bash
# La vista de bpftrace de la misma técnica (uno de sus ejemplos canónicos):
sudo bpftrace -e 'uretprobe:/bin/bash:readline { printf("%s: %s\n", comm, str(retval)); }'
```

TripleCross lo lleva más lejos con un keylogger de ssh completo y un módulo de *file tampering* (modificar a la fuga ficheros que el sistema lee). Y eso sin haber tocado un solo binario del disco.

## 7. Persistencia: mejor que un init.d

La vida de un programa eBPF:

- **Un prog cargado sobrevive a su cargador**: el filter de tc sigue montado en la interfaz después de que el binario que lo cargó haya muerto.
- **Pinning**: con `bpftool prog pin <id> /sys/fs/bpf/persistente`, el prog/map queda referenciado en `bpffs` y puede reengancharse o leerse más tarde.
- **Daemon en userspace**: al reboot los progs cargados se limpian, así que el acompañante userland (un servicio, una regla de udev) lo recarga. Ahí está la persistencia real: un `systemd` unit con una `ExecStart` inocente que ejecuta el loader.

El detalle perverso: no hay fichero `.ko`, no hay entrada en lsmod, no hay syscall inyectada — hay *servicios y filtros* que a la postre son lo mismo que un `docker-proxy` legítimo carga todos los días.

## 8. Límites honestos (para el atacante y para el defensor)

El sandbox se mantiene mientras *toda* esta lista no ocurra:

- **Sin bugs del verificador.** Históricamente, bugs del verificador (bounds tracking, ALU32, punteros mal tipados) dieron escaladas a LPE completos — el ejemplo canónico es CVE-2021-3490, explotado por investigadores en 2021. Un rootkit eBPF *puro* no escapa del sandbox; necesitaría encadenar un bug del verificador *además*. Pero ojo: los kernels con unprivileged BPF habilitado + un bug del verificador = escalada a root sin userland involvement.
- **No puede escribir structs del kernel** con las APIs legítimas, así que nada de parchear `sys_call_table` ni inyectar en el ring 0 — el rootkit eBPF opera *en las fronteras* del kernel: buffers hacia userland y paquetes en la red.
- **`CAP_BPF` o `CAP_SYS_ADMIN`**: si el atacante ya es root del host, no pasa nada nuevo. La amenaza real es el rootkit eBPF como *motor de persistencia y ocultación* post-compromise, no como initial access.

## 9. Detección

Lo incómodo para el defensor: casi todo lo que sigue es opcional, y en hosts sin `bpftool` instalado, invisible a primera vista.

**Baseline de progs cargados:**

```bash
sudo bpftool prog show          # progs cargados: tipo, nombre, tag, mem
sudo bpftool map show           # maps vivos (estado compartido)
sudo bpftool net show           # hooks tc/XDP por interfaz ← el gran olvidado
sudo bpftool cgroup tree        # progs enganchados a cgroups
cat /proc/net/... ; ip link show # filtros clsact inesperados
```

**Audit de la syscall de carga:**

```bash
auditctl -a always,exit -F arch=b64 -S bpf -F auid>=1000 -k ebpf_watch
# y para cubrir TODOS los eventos de carga (perf tracepoints):
auditctl -w /sys/kernel/debug/tracing/events/bpf/ -p wa -k ebpf_audit
```

**Configs que duelen al atacante:**

| Control | Efecto |
|---|---|
| `kernel.unprivileged_bpf_disabled=2` | Userland sin caps no carga nada (2 = hasta reboot) |
| `CAP_BPF`/`CAP_PERFMON` granular (≥5.8) | Quitar `CAP_SYS_ADMIN` ya no basta como coartada |
| Seccomp deny `bpf(2)` en contenedores/servicios | Un nginx no necesita cargar progs eBPF |
| No correr cargadores de eBPF en el host salvo stack conocido | Cilium/Falco/monitoring tienen nombres y tags reconocibles |

**Los IOCs que no fallan:**

- Progs eBPF con nombres raros, o cuyo `owner` no es un binario conocido.
- Filtros `clsact` en `eth0` que nadie de la plataforma ha creado.
- Un `bpffs` montado con objetos pinneados que nadie pidió.
- Processos userland "innocuos" con un `bpf()` syscall en su histórico (audit).
- Y la regla de oro: **boot desde medio íntegro** para auditar — un rootkit con componente userland puede adulterar la salida de `bpftool` en el host comprometido, así que el análisis fiable se hace offline.

## 10. Moral

eBPF es observable y extensible *porque* el kernel de forma deliberada permite engancharse a sus intestinos. Ese mismo punto de engache sirve para: monitoring (la mayoría), rootkits (algunos), y detección de rootkits (Falco, Tetragon y compañía son eBPF corriendo defensivamente).

El defensor moderno tiene eBPF *encima* del kernel: el atacante con CAP_BPF puede engancharse *a la misma altura* y hacer el MITM sobre los eventos antes de que lleguen a tu sensor. Si tu herramienta de detección deposita su confianza en datos que un eBPF malicioso puede reescribir, está leyendo la versión editada de la historia.

Un rootkit LKM era un invasor. Un rootkit eBPF es el *kernel mintiendo con cara seria*.

---

**Referencias**

- TripleCross: rootkit eBPF de referencia (MITM, keylogging, persistencia) — github.com/h3xduck/TripleCross
- bad-bpf: DEF CON 29, Pat Holloway — github.com/pathtofile/bad-bpf
- ebpfkit: PoC ofensivo de Datadog Security Labs
- BPFdoor: el nombre engañoso, análisis público de incident response (Cadet Blue)
- Kernel docs: `Documentation/bpf/` — el sandbox explicado por el kernel mismo
- [Tutorial eBPF + bcc-tools](*este blog*: `/tutoriales/ebpf-tutorial-bcc-tools/`)