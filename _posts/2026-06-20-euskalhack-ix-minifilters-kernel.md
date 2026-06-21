---
layout: single
title: "EuskalHack IX — Minifilters: Owning the High (and Low) Ground"
date: 2026-06-20
permalink: /conference/euskalhack-ix-minifilters-kernel/
excerpt: "Evasión completa de EDR en Windows sin parchear el kernel: doble hidratación via Cloud Files (cldflt.sys), redirect con bindflt.sys (altitud 409900 > AV 320000), ejecución de malware por FRN sin ruta. Kurosh Dabbagh de BlackArrow/Tarlogic."
categories: [conference]
tags: [euskalhack, euskalhack-ix, windows-kernel, minifilter, edr-evasion, bindflt, cldflt, frn, ntfs, blackarrow]
toc: true
toc_sticky: true
series: "EuskalHack IX"
header:
  og_image: /assets/images/og-preview.png
---

> **TL;DR (EN):** Complete EDR evasion on Windows without kernel patching. Technique: register a malicious Cloud Files sync provider, perform double hydration (first delivers legitimate goodware for EDR to approve, second delivers malware referenced only by NTFS File Reference Number with no visible path), execute via NtCreateProcessEx(FRN) — EDR sees no suspicious path. bindflt.sys (altitude ~409900) operates above most AV drivers (~320000). No SSDT patching, no PatchGuard trigger. Talk by Kurosh Dabbagh (BlackArrow/Tarlogic, GitHub @kudaes) at EuskalHack IX, June 2026.

---

> **Ponente:** Kurosh Dabbagh · [BlackArrow](https://www.blackarrow.net) / [Tarlogic](https://www.tarlogic.com) · GitHub: [@kudaes](https://github.com/kudaes) · X: [@_Kudaes_](https://x.com/_Kudaes_) · [LinkedIn](https://www.linkedin.com/in/kuroshda/)  
> **Congreso:** [EuskalHack IX](/conference/euskalhack-ix/) · Donostia, 19 de junio de 2026 · ES

---

## Contexto: la pila de minifilters de Windows

Los **minifilters** son drivers de kernel que se enganchan al **Filter Manager** (`fltmgr.sys`) para interceptar operaciones de I/O del sistema de archivos antes de que lleguen a NTFS.

Cualquier operación sobre el FS — lectura, escritura, creación, borrado, renombrado — genera una operación de I/O que **recorre toda la pila de minifilters** en orden de altitud:

```
Aplicación
    │
    ▼
I/O Manager
    │
    ▼
Filter Manager (fltmgr.sys)
    │
    ├── altitud ~409900: bindflt.sys   ← intercepta primero
    │
    ├── altitud  328010: WdFilter.sys  ← Windows Defender
    │
    ├── altitud ~180451: cldflt.sys    ← Cloud Files (OneDrive)
    │
    └── NTFS
```

**La altitud** (no "latitud") determina el orden de interceptación. **Altitud más alta = intercepta primero**. Si un minifilter a altitud alta rechaza una operación, los de altitud inferior (incluido el EDR) **nunca la ven**.

```powershell
# Ver todos los minifilters activos con sus altitudes
fltmc instances

# Salida ejemplo:
# Instance Name         Altitude     Frame
# bindflt               409900.00    0
# WdFilter              328010.00    0
# cldflt                180451.00    0
```

---

## Drivers protagonistas

### cldflt.sys — Cloud Files Filter Driver

Driver del sistema Cloud Files de Windows (la capa que hace funcionar OneDrive). Gestiona los **placeholders**: ficheros virtuales en disco que representan contenido en la nube aún no descargado.

Un placeholder:
- Aparece en el explorador como fichero normal (icono de nube)
- No ocupa espacio en disco
- Cuando se abre, el **sync provider** lo descarga (**hidratación**)
- Tiene atributos NTFS propios: `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`

### bindflt.sys — Bind Filter Driver

Driver que mapea rutas del FS a otras rutas (bind mount). Característica crítica:

```
bindflt.sys  →  altitud ~409900
WdFilter.sys →  altitud ~328010
                               ↑ diferencia de ~82000

bindflt intercepta ANTES que el AV/EDR → el EDR no ve lo que bindflt hace
```

### msmpeng.exe — Windows Defender

El proceso de Defender. Su driver de kernel (`WdFilter.sys`) opera en altitud ~328000. El objetivo del ataque: que analice un fichero legítimo y lo marque como limpio, para ejecutar malware después sin re-análisis.

---

## El ataque: doble hidratación con BindFlt

### Fase 1 — Registrar sync provider malicioso

```
El atacante registra un proceso propio como sync provider legítimo
para un directorio bajo su control.
Cualquier proceso puede registrarse como sync provider via la Cloud Files API.
```

### Fase 2 — Crear placeholder para goodware

```
Se crea un placeholder para certutil.exe (binario legítimo de Windows).
En disco solo existe el placeholder, no el binario real.
```

### Fase 3 — Primera hidratación → goodware

```
El EDR (o cualquier proceso) accede al placeholder.
Sync provider malicioso → entrega certutil.exe REAL
EDR analiza → LIMPIO ✓
El fichero queda marcado en caché como verificado.
```

### Fase 4 — Segunda hidratación → malware vía FRN

```
En la segunda solicitud, el sync provider entrega el MALWARE.
Pero el malware no tiene ruta en el FS — solo tiene FRN.
El EDR ya marcó el fichero como limpio → no re-analiza.
```

### Fase 5 — Ejecución via NtCreateProcessEx con FRN

```c
/* En lugar de: NtCreateProcess("C:\\Windows\\System32\\certutil.exe") */
/* Se llama con el FRN del malware directamente: */
NtCreateProcessEx(FileHandle_FRN, ...);

/* El malware se ejecuta desde un fichero sin ruta visible para el EDR */
```

### Fase 6 — bindflt redirige la ruta

```
bindflt.sys mapea: C:\Windows\System32\certutil.exe → C:\malware.exe
El EDR que monitoriza la ruta de certutil ve la ruta legítima.
Detrás de esa ruta está el malware — pero bindflt lo resuelve antes que el EDR.
```

### Resultado: evasión completa

```
✅ EDR vio certutil.exe real en la primera hidratación → caché limpio
✅ EDR ve ruta legítima via BindFlt → no re-analiza
✅ Ejecución via FRN bypasa detecciones path-based
✅ Sin parchear kernel → PatchGuard no se activa
```

---

## Conceptos técnicos clave

### FRN (File Reference Number)

Identificador único de un fichero en NTFS, basado en la entrada del MFT, **no en su ruta**:

```
MFT Entry #12345 ← FRN = 12345
  - Nombre en directorio: (ninguno)
  - Contenido: malware.exe

NtCreateProcessEx(FileHandle_de_FRN_12345)
→ ejecuta el binario del MFT entry #12345
→ sin ruta visible para el EDR
```

Los EDRs modernos basan sus detecciones en **rutas de ficheros** (path-based). Un proceso creado desde un FRN sin ruta es invisible para ese modelo.

### bindlink API

```c
/* Crear un bind mount: la ruta origen apunta a la ruta destino */
BindLink(
    L"\\Device\\HarddiskVolume3\\Windows\\System32\\certutil.exe",  /* origen */
    L"\\Device\\HarddiskVolume3\\payload.exe"                        /* destino */
);
/* Ahora: acceder a certutil.exe → bindflt redirige a payload.exe */
/* El EDR monitoriza certutil.exe y ve la ruta legítima            */
```

### fltFileWriteEx (FltWriteFileEx)

Función del kernel usada internamente en la hidratación. El sync provider malicioso usa esta función para escribir el contenido que decide (goodware o malware) en el fichero placeholder durante la hidratación.

---

## Por qué es robusto: sin tocar el kernel

```
Técnicas clásicas de evasión de EDR:
✗ Parchear SSDT       → PatchGuard lo detecta → BSOD
✗ Hook en syscalls    → PatchGuard / ELAM lo detecta
✗ Modificar IDT       → PatchGuard lo detecta

Esta técnica:
✓ Cloud Files API      → documentada y permitida por Microsoft
✓ bindlink API         → documentada y permitida
✓ NtCreateProcessEx   → syscall normal
✓ FRN                 → característica NTFS estándar
→ Cero interacción con estructuras protegidas por PatchGuard
```

---

## Conceptos relacionados

### Kernel Callbacks — detección que sí evade

El EDR se registra para notificaciones de eventos a nivel de kernel:

```c
/* El EDR registra callbacks via: */
PsSetCreateProcessNotifyRoutine(callback, FALSE);   /* creación de procesos */
PsSetCreateThreadNotifyRoutine(callback);           /* creación de hilos */
CmRegisterCallback(callback, NULL, &cookie);        /* cambios en registro */
```

El ataque via FRN evade el callback de proceso porque la imagen viene de un FRN sin ruta visible — el callback recibe información incompleta.

### ETW (Event Tracing for Windows)

Sistema de telemetría del kernel que los EDRs consumen. Puede bypasearse con "ETW patching":

```c
/* ETW patching — sobrescribir EtwEventWrite con RET para silenciar un provider */
BYTE ret_patch[] = { 0xC3 };  /* RET */
WriteProcessMemory(GetCurrentProcess(), EtwEventWrite, ret_patch, 1, NULL);
```

### Protecciones del EDR contra tamper

**PPL (Protected Process Light)** — `msmpeng.exe` corre como PPL. No puedes abrirlo con `OpenProcess()` para inyectar o terminarlo sin un driver con certificado de Microsoft.

**Tamper Protection (Defender)** — impide modificar la configuración de Defender desde el OS. Requiere Intune o acceso hardware para desactivarlo.

**ELAM (Early Launch Anti-Malware)** — driver que arranca antes que cualquier driver de terceros y verifica sus firmas. Primera línea antes de que el minifilter stack esté disponible.

### PatchGuard (KPP — Kernel Patch Protection)

Detecta en background modificaciones no autorizadas al kernel:

```
Protege:
- SSDT y Shadow SSDT
- IDT (Interrupt Descriptor Table)
- GDT (Global Descriptor Table)
- Tablas de syscall

Respuesta: BSOD inmediato con código de parada 0x109
```

Por eso el ataque de Dabbagh usa Cloud Files API y bindlink — APIs públicas que no tocan estas estructuras.

### ADS (Alternate Data Streams)

NTFS permite datos "ocultos" en cualquier fichero con `fichero:stream`:

```powershell
# Escribir en un ADS
echo "payload" > fichero.txt:stream_oculto

# Leer el ADS
Get-Content fichero.txt:stream_oculto

# Los minifilters interceptan operaciones sobre ADS también
```

### Ransomware y minifilters — la técnica inversa

El ransomware moderno usa la misma arquitectura en sentido contrario: un minifilter a altitud baja que intercepta lecturas y devuelve contenido cifrado "al vuelo", sin modificar el fichero en disco. El backup que lee el FS directamente obtiene datos cifrados, no el contenido real.

### Rangos de altitud de Microsoft

| Rango | Categoría |
|-------|----------|
| 420000+ | FSFilter Top |
| **~409900** | **bindflt.sys** ← por encima de todo |
| 400000-409999 | FSFilter Activity Monitor |
| **320000-329999** | **Anti-Virus / EDR** |
| 260000-269999 | FSFilter Replication |
| ~180000 | **cldflt.sys** (Cloud Files / OneDrive) |
| 140000-149999 | FSFilter Continuous Backup |

---

---

## EuskalHack IX — Serie completa

| # | Post |
|---|------|
| Índice | [Notas técnicas — todas las charlas](/conference/euskalhack-ix/) |
| 1 | [Agentic AI Supremacy — Is your AI a double-agent?](/conference/euskalhack-ix-agentic-ai/) |
| 2 | [Insiders: detección de amenazas internas](/conference/euskalhack-ix-insiders-ueba/) |
| 3 | [Hackeando videoporteros — root sin llamar al timbre](/conference/euskalhack-ix-videoportero-iot/) |
| 4 | [ATMs conectados a AWS: ¿qué podría salir mal?](/conference/euskalhack-ix-atms-aws/) |
| 5 | [Radar real con ESP32 por menos de 15€](/conference/euskalhack-ix-radar-esp32/) |
| 6 | [Análisis de vulnerabilidades de firmware](/conference/euskalhack-ix-firmware-analysis/) |
| 7 | **Minifilters: Owning the High (and Low) Ground** ← estás aquí |
