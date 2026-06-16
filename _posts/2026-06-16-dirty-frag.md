---
layout: single
title: "Dirty Frag — LPE en el kernel Linux via Page-Cache Write"
date: 2026-06-16
categories: [tutoriales, malware]
tags: [dirty-frag, cve-2026-43284, cve-2026-43500, kernel, privesc, lpe, ipsec, xfrm, rxrpc, page-cache]
excerpt: "Análisis de Dirty Frag (CVE-2026-43284 + CVE-2026-43500): escalada de privilegios determinista en el kernel Linux encadenando dos vulnerabilidades de escritura en page cache en los subsistemas xfrm-ESP y RxRPC."
permalink: /tutoriales/dirty-frag-lpe-kernel-linux/
header:
  image: "https://upload.wikimedia.org/wikipedia/commons/thumb/d/dd/XFS_v4_Linux_Kernel_Option.jpg/1920px-XFS_v4_Linux_Kernel_Option.jpg"
  caption: "Opciones del kernel Linux — Wikimedia Commons"

---

El 7 de mayo de 2026 se publicó **Dirty Frag**, una nueva clase de vulnerabilidad en el kernel Linux que permite escalar privilegios a root de forma determinista, sin race conditions y con una tasa de éxito muy alta. Descubierta y reportada por **Hyunwoo Kim (@v4bel)**, representa la extensión natural de la familia iniciada por Dirty Pipe y Copy Fail.

---

## CVEs implicados

| CVE | Subsistema | CVSS | Introducido | Parchado |
|-----|-----------|------|-------------|----------|
| CVE-2026-43284 | xfrm / ESP (IPsec) | 8.8 HIGH | 2017-01-17 (`cac2661c53f3`) | 2026-05-05 (`f4c50a4034e6`) |
| CVE-2026-43500 | RxRPC (AFS) | 7.8 HIGH | 2023-06-08 (`2dc334f1a63a`) | 2026-05-10 (`aa54b1d27fe0`) |

Nueve años de ventana para CVE-2026-43284. Eso dice mucho sobre la superficie de ataque que representa el subsistema de red del kernel.

---

## La clase del bug: Page-Cache Write

Dirty Frag pertenece a la misma familia que Dirty Pipe (CVE-2022-0847) y Copy Fail. La idea central es la misma: **escribir en el page cache de un fichero sin tener permisos de escritura sobre él**, lo que permite modificar contenido de ficheros de solo lectura en memoria.

En Dirty Pipe el vector era el splice en pipes. Aquí el vector son dos rutas distintas:

### CVE-2026-43284 — xfrm-ESP Page-Cache Write

El subsistema `xfrm` gestiona la transformación de paquetes IPsec. Los módulos `esp4` y `esp6` implementan el protocolo ESP (Encapsulating Security Payload). El bug se encuentra en la forma en que se mapean páginas durante el procesado de paquetes: es posible inducir al kernel a escribir en una página del cache que pertenece a un fichero sin privilegios de escritura.

### CVE-2026-43500 — RxRPC Page-Cache Write

`rxrpc` es el protocolo de transporte usado por AFS (Andrew File System). El bug sigue el mismo patrón: escritura no autorizada en page cache a través de la ruta de recepción de paquetes RxRPC.

---

## Por qué es relevante: sin race condition

La mayoría de LPEs en kernel requieren ganar una condición de carrera, lo que hace que el exploit sea probabilístico y a menudo cause kernel panic en los intentos fallidos. **Dirty Frag es un bug de lógica determinista**: no depende de ninguna ventana temporal, el kernel no entra en pánico si falla, y la tasa de éxito es muy alta.

Esto lo convierte en un vector especialmente atractivo para uso real, no solo para CTF.

---

## Exploit PoC

El PoC oficial está en [github.com/V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag):

```bash
git clone https://github.com/V4bel/dirtyfrag.git
cd dirtyfrag
gcc -O0 -Wall -o exp exp.c -lutil
./exp
```

**Importante:** después de ejecutar el exploit el page cache queda contaminado. Hay que limpiarlo antes de seguir usando el sistema:

```bash
echo 3 > /proc/sys/vm/drop_caches
```

O directamente reiniciar. No usar en sistemas no autorizados.

El exploit ha sido probado en:

- Ubuntu 24.04.4 — kernel `6.17.0-23-generic`
- RHEL 10.1 — `6.12.0-124.49.1.el10_1.x86_64`
- openSUSE Tumbleweed — `7.0.2-1-default`
- CentOS Stream 10 — `6.12.0-224.el10.x86_64`
- AlmaLinux 10 — `6.12.0`

---

## Impacto en entornos de contenedores

En despliegues con contenedores la cosa se complica: además de LPE local, la vulnerabilidad puede facilitar **container escape**. El PoC de escape no fue publicado en la divulgación inicial, pero el vector existe.

---

## ¿Estás expuesto?

Comprueba tu versión de kernel:

```bash
uname -r
```

Versiones parcheadas según Ubuntu:

| Release | Versión parcheada |
|---------|-------------------|
| 18.04 LTS | `4.15.0-251.263` / `5.4.0-231.251~18.04.1` |
| 20.04 LTS | `5.4.0-231.251` / `5.15.0-181.191~20.04.1` |
| 22.04 LTS | `5.15.0-181.191` / `6.8.0-124.124~22.04.1` |
| 24.04 LTS | `6.8.0-124.124` / `6.17.0-35.35~24.04.1` |

Actualizar:

```bash
sudo apt update && sudo apt upgrade
sudo reboot
```

Si no puedes actualizar el kernel, la mitigación temporal es descargar los módulos afectados:

```bash
# Deshabilitar esp4, esp6 y rxrpc
echo "install esp4 /bin/false" >> /etc/modprobe.d/dirty-frag-mitigation.conf
echo "install esp6 /bin/false" >> /etc/modprobe.d/dirty-frag-mitigation.conf
echo "install rxrpc /bin/false" >> /etc/modprobe.d/dirty-frag-mitigation.conf
```

Esto rompe IPsec (VPNs tipo StrongSwan) y AFS. Si los usas, la única opción es parchear.

---

## Contexto

Canonical confirmó que Microsoft verificó explotación activa el 8 de mayo de 2026. El embargo se rompió antes de que existieran parches disponibles, lo que obligó a publicar la mitigación el mismo día de la divulgación.

La genealogía `Dirty Pipe → Copy Fail → Dirty Frag` sugiere que la clase de bugs de escritura en page cache tiene más recorrido. No sería raro ver más variantes en subsistemas menos auditados del kernel.
