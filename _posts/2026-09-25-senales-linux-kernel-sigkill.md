---
layout: single
title: "Señales en el kernel de Linux: SIGKILL, SIGSTOP y la anatomía de una muerte de proceso"
date: 2026-09-25
categories: [tutoriales, analisis]
tags: [linux, kernel, signals, sigkill, sigstop, anti-debugging, red-team, malware-analysis, incident-response]
excerpt: "Cómo gestiona el kernel de Linux las señales: la cola de pendientes, las dos señales que ningún proceso puede capturar, por qué kill -9 a veces no mata, y cómo se aprovecha todo esto en ofensiva."
permalink: /tutoriales/senales-linux-kernel-sigkill/
---

Cualquiera que haya usado Linux un par de meses conoce `kill -9`. Lo que casi nadie conoce es lo que pasa *dentro* del kernel entre que escribes el comando y el proceso desaparece: por qué SIGKILL no se puede capturar, por qué a veces `kill -9` no mata nada, y por qué un malware puede convertirse en inmortal frente a tu `pkill`.

Este post desmonta el modelo de señales del kernel de Linux y lo mira desde la óptica que nos interesa: qué se puede hacer con ellas en ofensiva y qué se puede hacer con ellas para defenderte.

---

## Un mecanismo asíncrono muy antiguo

Una señal es la forma más antigua de IPC en UNIX: una notificación asíncrona que el kernel entrega a un proceso indicando que ha ocurrido un evento. No hay payload, no hay sesión, no hay negociación — solo un número y una acción asociada.

En el kernel, cada `task_struct` (una tarea: proceso o hilo) lleva tres conjuntos de bits que definen su relación con las señales:

| Conjunto | Significado |
|---|---|
| **Pending** | Señales recibidas y todavía sin entregar |
| **Blocked** | Señales que no se pueden entregar temporalmente |
| **Ignored** | Señales configuradas para ignorarse |

El flujo es simple: cuando alguien envía una señal (syscall `kill()`, `tgkill()`, o internamente `do_send_sig_info()`), el kernel la encola en el conjunto *pending* del proceso. La entrega real **no es inmediata**: la tarea comprueba su cola de pendientes al volver de cualquier syscall, al salir de una interrupción o antes de regresar a espacio de usuario (`get_signal()` en `kernel/signal.c`). Una señal es, a efectos prácticos, un flag que el kernel consulta en cada "cambio de carril".

Ahí es donde entra `sigaction()`: la tabla de handlers por señal de cada proceso. Un handler puede ser `SIG_DFL` (acción por defecto: terminar, ignorar, parar...), `SIG_IGN` (ignorar) o una función de usuario. El kernel salta al handler en modo usuario con la pila preparada y, opcionalmente, con un `ucontext` que contiene el estado de registros al momento de la interrupción — más adelante veremos que esto tiene jugo ofensivo.

---

## El catálogo: 31 señales estándar + 32 de tiempo real

El rango clásico va del 1 al 31. Del 34 al 64 están las señales de tiempo real (`SIGRTMIN` a `SIGRTMAX`), que son todas "de usuario": el kernel no les da semántica propia, se entregan en orden y se pueden encolar de forma fiable (una señal estándar repetida mientras está pendiente se colapsa en una sola; una real-time no — cada `sigqueue()` es una entrada).

Agrupando las estándar por lo que hacen:

- **Terminar el proceso:** `SIGHUP` (1), `SIGINT` (2), `SIGQUIT` (3), `SIGTERM` (15), `SIGPWR` (30), `SIGSYS` (31)
- **Muerte por culpa del propio proceso:** `SIGILL` (4), `SIGABRT` (6), `SIGFPE` (8), `SIGSEGV` (11), `SIGBUS` (7)
- **Control de tareas (job control):** `SIGTSTP` (20), `SIGTTIN` (21), `SIGTTOU` (22), `SIGCONT` (18), `SIGCHLD` (17)
- **Parada forzosa:** `SIGSTOP` (19)
- **Killing puro:** `SIGKILL` (9)
- **Depuración y trazado:** `SIGTRAP` (5)
- **Temporizadores:** `SIGALRM` (14), `SIGPROF` (27), `SIGVTALRM` (26), `SIGXCPU` (24), `SIGXFSZ` (25)
- **Eventos asíncronos:** `SIGPIPE` (13), `SIGIO` (29), `SIGWINCH` (28), `SIGURG` (23), `SIGSTKFLT` (16)
- **Definidas por el usuario:** `SIGUSR1` (10), `SIGUSR2` (12)

Las señales 32 y 33 no aparecen en `kill -l` porque glibc las usa internamente para hilos NPTL (cancelación y gestión del stack). Por eso en glibc `SIGRTMIN` es 34 y no 32.

---

## SIGKILL y SIGSTOP: las señales del kernel

En `prepare_signal()` (kernel/signal.c) hay un caso especial: `SIGKILL` (9) y `SIGSTOP` (19) no admiten ni handler, ni ignoración, ni bloqueo. Si intentas capturarlas, la llamada a `sigaction()` devuelve `EINVAL`; si están en la máscara de bloqueadas, el kernel las elimina de ella directamente.

El motivo es histórico y pragmático: sin una señal *intocable*, todo proceso con un bug en su manejador de señales (o un proceso malicioso con intenciones de no morir) sería inmortal. El kernel se reserva la llave de la bula.

La consecuencia práctica la conoces: `kill -15` (SIGTERM) es una petición educada que el proceso puede atender, procesar y hasta desoír; `kill -9` (SIGKILL) es el kernel desactivando esa tarea sin pasar por espacio de usuario — no se guardan buffers, no se ejecutan destructores, no hay handler de limpieza. En un análisis de malware, esto significa que **matar con SIGKILL destruye estado en memoria que habrías querido volcar** (claves, configuración, colas de red). Para respuesta a incidentes, la herramienta correcta es SIGSTOP.

---

## ¿Por qué kill -9 a veces no mata nada?

Tres escenarios clásicos donde SIGKILL "falla":

**1. Proceso en sueño ininterrumpible (`D state`).** Una tarea bloqueada en `TASK_UNINTERRUPTIBLE` (esperando I/O de disco o NFS, por ejemplo) no revisa su cola de señales. El kernel marca SIGKILL como pendiente, y el proceso muere... cuando despierte. Si el bloqueo es permanente (bug en un driver, NFS colgado), el proceso es un *unkillable*. En `/proc/PID/status` lo ves como `State: D`.

**2. Zombis.** El proceso ya está muerto; solo queda su entrada en la tabla de procesos a la espera de que el padre llame a `wait()`. No hay nada que matar — el que tiene que actuar es el padre (o init, si le enseñas al padre a morir).

**3. Tareas atrapadas por el kernel en bucle kernel-space.** Si la tarea está ejecutando una syscall larga o está en bucle en modo kernel, tampoco llega a procesar la señal hasta volver a un punto de entrega.

Desde Linux 3.2 existe además un bit especial por-tarea para SIGKILL que garantiza que un `kill -9` sobrevive a situaciones donde antes se perdía (procesos bajo ptrace, por ejemplo): `jobctl` lo encola directamente en la tarea y no en el grupo.

---

## El lado ofensivo de las señales

### Anti-debugging con SIGTRAP

Cuando un proceso está siendo trazado con `ptrace`, el depurador intercepta *todas* las señales que recibe el tracee antes de dejarlas pasar. Esto abre una vía clásica de anti-debug: el proceso se lanza a sí mismo una `SIGTRAP` y comprueba si la recibe su handler o si "alguien" la ha consumido antes.

```c
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile int got_trap = 0;

void handler(int sig) { got_trap = 1; }

int main(void) {
    signal(SIGTRAP, handler);
    raise(SIGTRAP);          // bajo un depurador, la señal la ve él, no el proceso
    if (!got_trap)
        puts("[!] Debugger detected");
    return 0;
}
```

La misma idea se aplica a `SIGSTOP`: si el proceso está traceado, el `SIGSTOP` lo deja en *group-stop* controlado por el tracer en lugar de en parada normal, y un proceso sofisticado puede detectar la diferencia de estado.

### Muerte del padre: PR_SET_PDEATHSIG

`prctl(PR_SET_PDEATHSIG, SIGKILL)` le pide al kernel: "si mi padre muere, mándame SIGKILL". Es la base de los watchdogs limpios, pero también de implantas que se suicidan en cuanto matas al proceso de lanzamiento — mata la cadena de padre e hijo en una sola jugada. Ojo con dos detalles: se limpia en `execve()` de binarios setuid y hay una carrera clásica si el "padre" original ya murió antes de la llamada.

### Control de flujo por excepción

Como el kernel entrega un `ucontext` completo al handler, un proceso puede manipular su propio RIP y redirigir el flujo de ejecución. Capturar `SIGSEGV`/`SIGFPE`/`SIGILL` y saltar a otra dirección es una técnica real de ofuscación (exception-oriented programming), muy usada en malware y en protectores comerciales:

```c
#include <signal.h>
#include <ucontext.h>

void segv_handler(int sig, siginfo_t *si, void *uctx) {
    ucontext_t *u = (ucontext_t *)uctx;
    u->uc_mcontext.gregs[REG_RIP] = (unsigned long)secret_function;
}

int main(void) {
    struct sigaction sa = { .sa_sigaction = segv_handler, .sa_flags = SA_SIGINFO };
    sigaction(SIGSEGV, &sa, NULL);
    *(volatile int *)0 = 0;   // el "crash" es, en realidad, un salto
    return 0;
}
```

Para el analista, esto rompe la intuición de "SIGSEGV = bug": en malware moderno, un SIGSEGV puede ser el *salto de trampolín* más importante del binario. Una huella de comportamiento a vigilar en sandbox.

### Congelar sin matar: SIGSTOP en respuesta a incidentes

`kill -STOP` es la herramienta del primer Respondedor en Linux: detiene el proceso *sin ejecutar ni una instrucción más*, sin destruir memoria y sin darle la opción de limpiarse. Mientras está en `T (stopped)`, puedes volcar su memoria (`/proc/PID/mem`, `gcore`), capturar descriptores en `/proc/PID/fd`, y analizar calma. Malware con hilo de *deadman* que vigila y limpia si recibe SIGTERM no hace nada frente a SIGSTOP: ni siquiera se entera.

La contrapartida ofensiva también existe: un implant puede hacer `SIGSTOP` sobre sí mismo ante un `kill -TERM` sospechoso y reanudarse después (`SIGCONT`), y procesos que atrapan SIGTERM para fingir limpieza mientras se preparan para saltar a otra vía.

---

## Observabilidad: leer las máscaras de señales

Cada proceso expone sus conjuntos de bits en `/proc/PID/status`:

```text
SigPnd: 0000000000000000   pendientes
SigBlk: 0000000000000000   bloqueadas
SigIgn: 0000000000000004   ignoradas  (bit 2 → señal 3, SIGQUIT en este ejemplo)
SigCgt: 0000000180000000   capturadas
```

El bit *n*-ésimo es la señal *n*. `SigCgt` de un proceso te dice de un vistazo qué señales tiene instrumentadas — un implant que captura `SIGTERM` y `SIGINT` aparece ahí a la legua. Combinado con `auditd` para registrar llamadas a `kill()`/`tkill()`:

```text
-a always,exit -F arch=b64 -S kill,tgkill -k signal-watch
```

...tienes telemetría suficiente para cazar tanto a quien mata procesos críticos como al que usa señales como canal encubierto (sí: las señales también se han usado como covert channel, y con poco margen de error).

---

## Cierre

- Las señales son flags asíncronos entregados en puntos de retorno al espacio de usuario; nada se ejecuta "al instante".
- `SIGKILL` y `SIGSTOP` son reservadas del kernel: no se capturan, no se bloquean, no se ignoran.
- `kill -9` no mata procesos en `D state` ni zombis — y destruye evidencia en memoria cuando sí mata.
- En ofensiva: anti-debug con SIGTRAP, PDEATHSIG para cadenas que se auto-limpian, control de flujo por excepción, y SIGSTOP como herramienta de doble filo.
- En defensiva: SIGSTOP para congelar y volcar, `SigCgt` para detectar handlers sospechosos, auditd para tener registro de quién le dispara a quién.

La próxima vez que escribas `kill -9`, ya sabes qué está pasando debajo: el kernel ignorando cortésmente todo lo que el proceso haya preparado y vaciando la tarea de la tabla de procesos. A veces es lo que quieres. A veces es justo lo que el atacante esperaba.