---
layout: single
title: "Token Impersonation y la Familia Potato: Escalada de Privilegios en Windows"
date: 2026-07-13
categories: [tutoriales]
tags: [windows, privesc, tokens, potato, seimpersonateprivilege, juicypotato, godpotato, printspoofer, offensive]
excerpt: "Cómo SeImpersonatePrivilege convierte una shell de servicio en SYSTEM: el modelo de tokens de Windows, la cadena de Rotten a GodPotato y PrintSpoofer."
permalink: /tutoriales/token-impersonation-potato-attacks/
toc: true
toc_sticky: true
---

Conseguir ejecución de código como cuenta de servicio (`IIS APPPOOL\DefaultAppPool`, `NT AUTHORITY\NETWORK SERVICE`, `mssql`) es un escenario habitual en pentesting. El siguiente paso —SYSTEM— se basa casi siempre en el mismo primitivo: **token impersonation** via `SeImpersonatePrivilege`. Este post explica el mecanismo desde los cimientos y recorre la evolución de las técnicas que lo explotan.

## El modelo de tokens de Windows

Windows controla el acceso a recursos mediante **access tokens**. Cada proceso tiene un **primary token** que representa la identidad con la que fue creado. Cuando un thread necesita actuar bajo una identidad diferente —sin cambiar la del proceso completo—, usa un **impersonation token**.

Las funciones de la API relevantes:

| Función | Uso |
|---|---|
| `OpenProcessToken` | Obtener el token de un proceso |
| `DuplicateTokenEx` | Duplicar un token (cambiar tipo o nivel) |
| `ImpersonateLoggedOnUser` | Activar impersonation en el thread actual |
| `SetThreadToken` | Asignar un token a un thread concreto |
| `CreateProcessWithTokenW` | Crear proceso bajo otro token |

Los tokens tienen un **impersonation level** que determina hasta qué punto se puede usar la identidad capturada:

- `SecurityAnonymous` — no se puede inspeccionar ni impersonar
- `SecurityIdentification` — se puede inspeccionar la identidad pero no impersonar
- `SecurityImpersonation` — impersonación local
- `SecurityDelegation` — impersonación sobre red

Para algo útil (spawnar un proceso como SYSTEM) se necesita nivel `SecurityImpersonation` o superior, y el privilegio adecuado en el proceso atacante.

## SeImpersonatePrivilege

Este privilegio permite a un thread **suplantar al cliente de cualquier conexión** que llegue al proceso. La descripción oficial de Windows es "Impersonate a client after authentication".

Por diseño, Windows lo asigna a:
- Cuentas de servicio locales (`Local Service`, `Network Service`)
- Application pools de IIS (`IIS APPPOOL\*`, `IUSR`)
- Instancias de SQL Server
- Cualquier servicio COM que actúe como servidor de autenticación

La lógica es válida: un servidor web necesita poder actuar como el usuario que hace la petición HTTP. El abuso viene de que, si puedes provocar que una cuenta privilegiada se **autentique contra tu proceso**, capturas un token de impersonation de esa cuenta.

Verificar los privilegios desde una shell de servicio:

```cmd
whoami /priv
```

La presencia de `SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege` con estado `Enabled` es el punto de entrada para la escalada.

## El primitivo de autenticación forzada

La raíz de toda la familia Potato es este mismo esquema:

1. Crear un endpoint local (named pipe, puerto TCP, socket COM)
2. Forzar a una cuenta privilegiada a autenticarse contra él
3. Capturar el token resultante
4. Impersonar ese token → SYSTEM

El método para forzar la autenticación ha cambiado con cada versión del SO y los parches de Microsoft. De ahí la proliferación de "Potatoes".

## La familia Potato

### Hot Potato (2016)

Primer exploit público que encadenó tres técnicas:
1. **NBNS spoofing** — responder a consultas NetBIOS Name Service con la IP local
2. **WPAD injection** — servir un proxy WPAD malicioso para interceptar tráfico HTTP
3. **NTLM relay** — capturar y redirigir la autenticación NTLM que Windows Update hacía al servidor WPAD

Funcionó en Windows 7/8/Server 2008R2. Microsoft cortó la cadena con actualizaciones del mismo año.

### Rotten Potato (2016)

Más directo: usa la API DCOM sin necesidad de spoofing de red. Cuando un cliente COM solicita activar un objeto en sesión 0, Windows inicia una autenticación NTLM local. Rotten Potato:

1. Abre un named pipe local
2. Llama a `CoGetInstanceFromIStorage` para que `NT AUTHORITY\SYSTEM` se conecte al pipe
3. Captura el token via `NtImpersonateThread`
4. Usa ese token para crear un proceso SYSTEM

Requería integración con Meterpreter o acceso directo a `ImpersonateNamedPipeClient`. Funcionó hasta Windows 10 1803.

### Juicy Potato (2018)

La mejora clave fue la **selección de CLSID**. Rotten Potato usaba un CLSID fijo que Microsoft fue bloqueando progresivamente. Juicy Potato expone ese parámetro al usuario:

```cmd
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c net localgroup administrators hacker /add" -t * -c {CLSID}
```

El parámetro `-c` acepta cualquier CLSID de los objetos COM que se activan como SYSTEM (hay listas públicas por versión de Windows). El puerto `-l` es donde DCOM se autenticará localmente.

Microsoft respondió bloqueando el abuso de DCOM desde sesión 0 en Windows 10 1809 y Server 2019.

### Sweet Potato (2020)

Combina las técnicas anteriores con un vector adicional: abusar de `StorSvc` (un servicio RPC que corre como SYSTEM). El proceso es similar pero va por una ruta RPC diferente, lo que le permite funcionar en algunos entornos donde Juicy Potato ya no aplica.

### GodPotato (2023)

La iteración más reciente y la más compatible. En lugar de depender de CLSIDs específicos, intercepta la comunicación RPC entre cliente y servidor COM sin las restricciones introducidas en 1809. Soporta Windows 2012 hasta Server 2022 y Windows 10/11.

```cmd
GodPotato.exe -cmd "cmd /c whoami"
```

Para shell reversa directamente:

```cmd
GodPotato.exe -cmd "cmd /c powershell -enc BASE64_PAYLOAD"
```

No requiere selección de CLSID ni configuración adicional. Es el punto de partida recomendado en entornos modernos si se confirma `SeImpersonatePrivilege`.

## PrintSpoofer

Una técnica paralela que abusa del protocolo **MS-RPRN** (Print Spooler) en lugar de DCOM. El mecanismo:

1. Crear un named pipe con path del formato `\\HOSTNAME\pipe\NOMBRE`
2. Llamar a `RpcRemoteFindFirstPrinterChangeNotification` apuntando al pipe
3. El servicio Spooler (SYSTEM) se conecta al pipe para notificar cambios
4. `ImpersonateNamedPipeClient` captura el token → SYSTEM

```cmd
PrintSpoofer64.exe -i -c cmd
```

El flag `-i` lanza el proceso en sesión interactiva. Útil cuando se quiere una shell en la misma consola del proceso actual.

Funciona en Windows 10/Server 2019 sin parches del Spooler. Muchas organizaciones tienen Print Spooler activo aun después de PrintNightmare (CVE-2021-1675) porque solo lo deshabilitan en DCs pero no en servidores miembro.

## Flujo completo de ataque

```
Shell de servicio (SeImpersonatePrivilege Enabled)
    │
    ├─ GodPotato / JuicyPotato   (DCOM abuse)
    │       └─→ CreateProcessWithTokenW → cmd.exe como SYSTEM
    │
    └─ PrintSpoofer              (MS-RPRN abuse)
            └─→ ImpersonateNamedPipeClient → cmd.exe como SYSTEM
```

Desde la shell SYSTEM se puede volcar credenciales con Mimikatz, crear usuarios locales, o moverse lateralmente según el contexto del entorno.

## Detección

**Event IDs relevantes:**

| Event ID | Canal | Descripción |
|---|---|---|
| 4672 | Security | Special privileges assigned to new logon |
| 4624 | Security | Logon — tipo 3 anómalo para procesos locales |
| 4697 | Security | Service installed in the system |
| 4688 | Security | Process creation (si auditing habilitado) |

**Señales de comportamiento:**
- Proceso de baja integridad creando named pipes con nombres no reconocidos
- Llamadas a `CoGetInstanceFromIStorage` desde cuentas de servicio no privilegiadas
- Print Spooler conectándose a pipes externos al propio servicio
- `CreateProcessWithTokenW` desde un proceso hijo de IIS o SQL

**Mitigaciones:**
- Eliminar `SeImpersonatePrivilege` de cuentas de servicio via GPO (`Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment`) si no es necesario
- Deshabilitar Print Spooler en servidores que no lo requieran
- Aplicar el hardening de DCOM (KB5004442) que Microsoft publicó en 2021-2022
- Usar Managed Service Accounts (gMSA) con privilegios mínimos
- Monitorizar `JuicyPotato.exe`, `GodPotato.exe`, `PrintSpoofer.exe` por hash en el EDR

## Referencias

- Rotten Potato: foxglovesecurity.com — "Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM" (2016)
- Juicy Potato: github.com/ohpe/juicy-potato
- PrintSpoofer: itm4n.github.io — "PrintSpoofer – Abusing Impersonation Privileges on Windows 10 and Server 2019"
- GodPotato: github.com/BeichenDream/GodPotato
- MSDN — Access Tokens: learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens
