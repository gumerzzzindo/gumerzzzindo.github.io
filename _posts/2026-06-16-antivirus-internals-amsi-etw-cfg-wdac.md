---
layout: single
title: "Anatomía de un Antivirus moderno: componentes, detección, AMSI, ETW, CFG y WDAC"
date: 2026-06-16
categories: [tutoriales, malware]
tags: [antivirus, edr, amsi, etw, cfg, wdac, heuristica, sandbox, windows-internals, deteccion]
excerpt: "Cómo funciona realmente un antivirus moderno por dentro: motores de firma y heurística, sandboxing, y las tres piernas de la telemetría de Windows que lo alimentan — AMSI, ETW, CFG y WDAC."
permalink: /tutoriales/antivirus-internals-amsi-etw-cfg-wdac/
header:
  image: "https://upload.wikimedia.org/wikipedia/commons/thumb/6/60/Bitdefender_Awards.jpg/1920px-Bitdefender_Awards.jpg"
  caption: "Premios de un antivirus — Wikimedia Commons"

---

Cuando alguien dice "el antivirus me detectó" suele imaginar un único proceso comparando hashes contra una lista negra. La realidad de un AV/EDR moderno (Defender, CrowdStrike, SentinelOne, etc.) es una pila de varios motores independientes que se alimentan de fuentes de telemetría muy distintas del sistema operativo. Entender esa pila es la base para entender por qué algo se detecta — y por qué algo no.

Este post recorre los componentes principales y las cuatro tecnologías de Windows que hacen posible la detección moderna: **AMSI**, **ETW**, **CFG** y **WDAC**.

---

## La pila de un AV moderno

Un antivirus actual no es un motor, son varios trabajando en capas, cada uno con coste y momento de ejecución distintos:

```
[1] Filtro de sistema de archivos (minifilter driver)
     │  intercepta cada apertura/escritura/ejecución de fichero
     ▼
[2] Motor de firmas (signature-based)
     │  hash, patrones de bytes, YARA
     ▼
[3] Motor heurístico / estático
     │  análisis del fichero sin ejecutarlo
     ▼
[4] AMSI — inspección de contenido en tiempo de ejecución
     │  scripts, macros, payloads in-memory
     ▼
[5] Sandbox / emulación dinámica
     │  ejecución controlada para ver el comportamiento real
     ▼
[6] Telemetría de comportamiento en runtime (ETW + kernel callbacks)
     │  qué hace el proceso una vez vivo en el sistema
     ▼
[7] Motor de ML / cloud lookup
     │  reputación, clustering, modelos entrenados
```

Cada capa existe porque la anterior tiene un punto ciego conocido. El malware moderno está diseñado para sobrevivir a las primeras capas y morir en algún punto más adelante — o para nunca tocar disco y evitar el minifiltro por completo.

---

## Motor de firmas: la primera línea, la más débil

El enfoque clásico: el AV mantiene una base de datos de hashes (MD5/SHA256) y patrones de bytes conocidos. Si el fichero coincide, se bloquea.

Problema evidente: cualquier cambio de un byte rompe el hash, y los packers/crypters automatizan ese cambio en segundos. Las firmas siguen siendo útiles para malware commodity de distribución masiva (no vale la pena para el atacante variar cada muestra), pero son inútiles contra nada dirigido.

```yara
rule Suspicious_PE_Packed
{
    strings:
        $upx = "UPX0" 
        $mz = { 4D 5A }
    condition:
        $mz at 0 and $upx
}
```

Las reglas YARA son la evolución natural de la firma: en vez de un hash exacto, buscan patrones estructurales (secciones, imports, strings) que toleran variación. Siguen siendo estáticas — no ejecutan nada.

---

## Heurística: inferir intención sin ejecutar

La heurística estática analiza el binario en busca de **rasgos sospechosos** sin correrlo: imports inusuales (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` juntos huelen a process injection), entropía alta en secciones (indicio de empaquetado/cifrado), ausencia de tabla de imports normal, certificados de firma inválidos, strings ofuscadas, o un PE que declara más memoria de la que usa.

El motor asigna una puntuación a cada rasgo y, al superar un umbral, dispara una alerta sin que exista una firma exacta. Es lo que permite detectar variantes nunca vistas de una familia conocida — y también la fuente principal de falsos positivos: herramientas de pentesting legítimas (Mimikatz, Cobalt Strike, incluso PowerShell con ofuscación) disparan los mismos patrones que el malware real.

La heurística dinámica va un paso más allá: ejecuta el binario en un entorno controlado y puntúa el comportamiento observado, no solo la estructura estática. Eso ya es sandboxing.

---

## Sandbox: ejecutar para ver qué hace de verdad

Cuando la estática no es suficiente, el AV detona la muestra en un entorno aislado — máquina virtual, contenedor o emulador de instrucciones — y observa:

- Llamadas a la API de Windows (creación de procesos, escritura en registro, conexiones de red)
- Ficheros creados/modificados
- Persistencia (tareas programadas, claves Run, servicios)
- Tráfico de red generado (C2 beaconing, exfiltración)

```
muestra.exe
   │
   ▼
[sandbox] VM aislada, sin red real (o red simulada)
   │
   ├─ hook de API Win32 ──► registra cada syscall relevante
   ├─ monitor de sistema de archivos ──► drops y modificaciones
   └─ monitor de red ──► IOCs de C2
   │
   ▼
[veredicto] benigno / sospechoso / malicioso
```

El malware moderno detecta sandboxes de forma activa: comprueba el número de cores, la RAM disponible, artefactos de hipervisor en el registro, tiempos de ejecución anómalamente rápidos (indicio de aceleración de reloj), o simplemente duerme varios minutos esperando que el análisis automático tenga timeout. Las técnicas de evasión de sandbox (`anti-VM`, `anti-debug`, `sleep obfuscation`) son hoy un módulo casi obligatorio en cualquier loader serio.

---

## AMSI: el final del "fileless es invisible"

**AMSI (Antimalware Scan Interface)** es la pieza que cerró una de las evasiones más usadas durante años: ejecutar payloads directamente en memoria vía scripts (PowerShell, VBScript, JScript, macros de Office) sin tocar disco, evitando así el minifiltro de ficheros y el motor de firmas tradicional.

AMSI es una API que Microsoft expone para que los motores de scripting (PowerShell, WSH, Office VBA, .NET) envíen el **contenido descifrado/desofuscado** al AV justo antes de ejecutarlo, sin importar cuántas capas de ofuscación tenía el script originalmente.

```
script.ps1 (ofuscado, base64, múltiples capas)
     │
     ▼
[motor PowerShell] deofusca y prepara para ejecutar
     │
     ▼
[AMSI.dll] AmsiScanBuffer() ──► envía el contenido en claro al AV
     │
     ▼
[AV registrado en AMSI] escanea el buffer
     │
     ├─ limpio ──► continúa la ejecución
     └─ malicioso ──► AMSI_RESULT_DETECTED, ejecución bloqueada
```

Lo importante: AMSI ve el script **después** de deofuscarse pero **antes** de ejecutarse, da igual cuántas capas de `[Convert]::FromBase64String` o `-replace` se hayan usado para esconderlo. Esto es lo que hizo que la ofuscación de PowerShell dejara de ser una técnica de evasión fiable por sí sola a partir de Windows 10.

Las técnicas de bypass de AMSI (parchear `AmsiScanBuffer` en memoria, forzar una excepción en la inicialización, parchear el patrón de bytes conocido) son justamente un ataque directo contra esta interfaz, no contra el AV en sí — si se rompe AMSI, el AV vuelve a quedar ciego ante scripts en memoria.

---

## ETW: la telemetría que ve todo lo demás

**ETW (Event Tracing for Windows)** es el sistema de logging nativo del kernel de Windows. No fue diseñado como herramienta de seguridad — existe desde Windows 2000 para diagnóstico de rendimiento — pero hoy es la columna vertebral de la telemetría de cualquier EDR serio.

Los providers de ETW relevantes para seguridad incluyen:

| Provider | Qué expone |
|----------|------------|
| `Microsoft-Windows-Threat-Intelligence` | Llamadas API sensibles (inyección de procesos, manipulación de tokens) |
| `Microsoft-Windows-Kernel-Process` | Creación/terminación de procesos |
| `Microsoft-Windows-Kernel-Network` | Conexiones de red a nivel kernel |
| `Microsoft-Windows-PowerShell` | Bloques de script ejecutados (complementa a AMSI) |
| `Microsoft-Windows-DotNETRuntime` | Carga de assemblies .NET, JIT |

```
proceso en ejecución
     │
     ▼
[kernel] genera eventos ETW en puntos instrumentados
     │
     ▼
[EDR] consumer suscrito al provider relevante
     │
     ▼
[correlación] secuencia de eventos ──► patrón de ataque
```

La ventaja sobre los hooks de userland clásicos (inline hooking de funciones ntdll) es que ETW vive en el kernel y es mucho más difícil de manipular desde un proceso en userland sin privilegios elevados. Por eso buena parte del malware moderno de gama alta incluye módulos de **ETW patching** — parchear `EtwEventWrite` en memoria para que los eventos generados por el propio proceso nunca lleguen al consumer del EDR. Es la misma filosofía que el bypass de AMSI, aplicado a un canal distinto.

---

## CFG: Control Flow Guard, mitigación a nivel de exploit

**CFG (Control Flow Guard)** no detecta malware — mitiga una clase entera de técnicas de explotación. Es una protección a nivel de compilador + runtime que valida que las llamadas indirectas (a través de punteros a función) solo puedan saltar a destinos válidos conocidos en tiempo de compilación.

```
código normal:
   call [puntero_funcion]   ──► salta directamente

código con CFG:
   call _guard_check_icall  ──► ¿el destino está en la bitmap de destinos válidos?
        │
        ├─ sí  ──► call [puntero_funcion]
        └─ no  ──► __fastfail() / crash controlado
```

Esto rompe técnicas clásicas de explotación de memoria como ROP (Return-Oriented Programming) cuando dependen de saltar a direcciones arbitrarias dentro del espacio de direcciones del proceso. Un binario compilado con `/guard:cf` (MSVC) genera una bitmap de todas las direcciones válidas como destino de llamada indirecta; cualquier intento de desviar el flujo de ejecución hacia una dirección fuera de esa bitmap termina en un crash en vez de en ejecución de código arbitrario.

Relevancia para el AV/EDR: muchos toolkits de inyección de shellcode (`CreateRemoteThread` + `WriteProcessMemory` apuntando a una dirección arbitraria) chocan con CFG si el proceso destino lo tiene activado, porque la dirección inyectada no está en la bitmap de destinos válidos. No es una bala de plata — existen variantes como `CallWindowProc` o el abuso de gadgets ya marcados como válidos para saltarla — pero eleva considerablemente el coste de las técnicas de inyección más simples y obliga al atacante a buscar primitivas más sofisticadas.

```powershell
# Comprobar si un proceso tiene CFG activo
Get-ProcessMitigation -Name notepad.exe | Select-Object -ExpandProperty CFG
```

---

## WDAC: control de qué puede ejecutarse, no detección de qué es malo

**WDAC (Windows Defender Application Control)** cambia por completo el modelo de defensa: en vez de intentar reconocer lo malicioso (blacklisting, que es lo que hacen firmas, heurística y sandbox), define explícitamente **qué binarios, scripts y drivers tienen permiso para ejecutarse** (whitelisting/allowlisting) y bloquea todo lo demás por defecto.

```
modelo tradicional (AV):
   ejecutar binario ──► ¿está en la lista negra? ──► no ──► permitir

modelo WDAC:
   ejecutar binario ──► ¿está en la política permitida? ──► no ──► bloquear
```

Una política de WDAC se construye sobre reglas como certificado de firma del publisher, hash del fichero, ruta de origen o atributos del PE, y se aplica a nivel de kernel — afecta a ejecutables, DLLs, drivers, scripts de PowerShell y MSI. A diferencia de AppLocker (su predecesor, basado en userland), WDAC se aplica antes de que el código llegue a ejecutarse, lo que lo hace mucho más resistente a bypass desde el propio proceso.

```xml
<!-- Fragmento simplificado de una política WDAC -->
<FileRules>
  <Allow ID="ID_ALLOW_A_1" FriendlyName="Microsoft Signed"
         FileName="*" MinimumFileVersion="0.0.0.0" />
</FileRules>
<Signers>
  <Signer ID="ID_SIGNER_MS" Name="Microsoft Code Signing PCA">
    <CertRoot Type="TBS" Value="..." />
  </Signer>
</Signers>
```

El coste de WDAC es operativo: cualquier herramienta legítima no incluida en la política deja de ejecutarse, lo que exige un proceso de gestión de excepciones constante. Por eso se ve mucho más en entornos corporativos con superficie de aplicaciones controlada (kioscos, servidores críticos, estaciones de trabajo reguladas) que en equipos de usuario final, donde el coste de mantenimiento sería inviable.

Desde la perspectiva del atacante, WDAC es mucho más duro de evadir que un AV basado en detección: no hay firma que esquivar ni heurística que evitar disparar, porque el binario simplemente no está en la lista de lo permitido. Las técnicas contra WDAC pasan por **LOLBins firmados por Microsoft** que ya están en la política permitida (living-off-the-land binaries como `mshta.exe`, `regsvr32.exe`, `installutil.exe`) o por explotar vulnerabilidades en binarios firmados que sí están permitidos.

---

## Cómo se combinan en la práctica

Ningún componente funciona aislado. Un ataque típico con PowerShell ofuscado en memoria pasa por varias capas simultáneamente:

```
1. WDAC         ──► ¿powershell.exe está permitido por política?      sí, lo está
2. AMSI         ──► el motor de PowerShell envía el script deofuscado al AV
3. Heurística   ──► patrones del script (Invoke-Expression + descarga remota) puntúan alto
4. ETW          ──► Microsoft-Windows-PowerShell registra el bloque de script ejecutado
5. CFG          ──► si el script intenta inyectar shellcode en otro proceso, CFG puede bloquear el salto
6. Sandbox/ML   ──► si nada anterior detonó, el comportamiento runtime se correla en la nube
```

La razón por la que el malware de gama alta invierte tanto esfuerzo en parchear AMSI, parchear ETW y evitar APIs que activen CFG no es casualidad: son los puntos de instrumentación que Microsoft fue añadiendo precisamente porque las capas anteriores (firmas, heurística estática) se quedaron cortas. Cada bypass nuevo suele tener una contramedida correspondiente en el siguiente Patch Tuesday — es una carrera continua, no un estado final.

---

## Referencias

- [Microsoft Learn — Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/windows/win32/amsi/antimalware-scan-interface-portal)
- [Microsoft Learn — Event Tracing for Windows (ETW)](https://learn.microsoft.com/windows/win32/etw/event-tracing-portal)
- [Microsoft Learn — Control Flow Guard](https://learn.microsoft.com/windows/win32/secbp/control-flow-guard)
- [Microsoft Learn — Windows Defender Application Control (WDAC)](https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/wdac)
- [MITRE ATT&CK — Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005/)