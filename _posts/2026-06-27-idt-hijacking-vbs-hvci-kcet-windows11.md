---
layout: single
title: "IDT Table Hijacking bajo VBS, HVCI y kCET en Windows 11"
date: 2026-06-27
categories: [research, windows-internals]
tags: [kernel, exploitation, hvci, vbs, kcet, idt, privilege-escalation, data-only, windows11, exploitpack]
excerpt: "ExploitPack publica una técnica para secuestrar la Interrupt Descriptor Table sin tocar código protegido por HVCI — escalada a SYSTEM desde usuario, sin CVE, en Windows 11 con todas las protecciones activas."
permalink: /research/idt-hijacking-vbs-hvci-kcet/
header:
  og_image: /assets/images/og-preview.png
---

El equipo de [ExploitPack](https://www.exploitpack.com) acaba de publicar una investigación sobre una técnica que consigue escalar privilegios a SYSTEM en Windows 11 con VBS, HVCI y kCET activos simultáneamente — sin CVE, sin driver firmado y sin inyectar código en el kernel.

El artículo original: [IDT Table Hijacking under VBS/HVCI/kCET in Windows 11](https://www.exploitpack.com/blogs/news/idt-table-hijacking-under-vbs-hvci-kcet-in-windows-11)

---

## Contexto: las tres protecciones

Antes de entrar en la técnica, hay que entender qué está activo y por qué importa:

| Protección | Qué hace |
|---|---|
| **VBS** (Virtualization-Based Security) | Aísla el kernel en una región protegida por el hypervisor |
| **HVCI** (Hypervisor-Protected Code Integrity) | Impide que código no firmado se ejecute en modo kernel |
| **kCET** (Kernel Control-flow Enforcement) | Protege el flujo de control del kernel contra ROP/JOP chains |

Las tres juntas forman la defensa en profundidad más dura que Microsoft ofrece actualmente. Con HVCI activo, modificar páginas de kernel directamente causa un check de integridad que bloquea la operación.

---

## La IDT: qué es y por qué es un objetivo

La **Interrupt Descriptor Table (IDT)** es una estructura del procesador que define qué función del kernel ejecutar ante cada tipo de interrupción. Cada entrada (llamada "gate") contiene la dirección del handler y los atributos de seguridad del salto.

```
Offset 0x00  2B  Dirección del handler (bits 0-15)
Offset 0x02  2B  Segment Selector
Offset 0x04  1B  Interrupt Stack Table
Offset 0x05  1B  Tipo de gate (Present, DPL, tipo)
Offset 0x06  2B  Dirección del handler (bits 16-31)
Offset 0x08  4B  Dirección del handler (bits 32-63)
Offset 0x0C  4B  Reservado
```

Controlar una entrada de la IDT significa redirigir la ejecución al código propio con privilegios de kernel. El problema: HVCI protege las páginas donde reside la IDT. Escribir directamente en ellas está bloqueado.

---

## La técnica: Data-Only + FWA pages

La investigación de ExploitPack parte de un primitivo que llaman **DOG (Data Only Gadgets)** — modificaciones exclusivamente de datos, sin inyección de código ejecutable. Ya lo usaron antes para atacar la SSDT y la Shadow SSDT. Esta vez el objetivo es la IDT.

### Free Writable Areas (FWA)

La CPU tiene acceso a toda la RAM física, incluidas zonas que el sistema operativo no gestiona: huecos entre allocaciones, páginas fuera del rango managed del SO, etc. Estas páginas son **físicamente accesibles** pero no aparecen en el mapa de memoria del kernel.

El proceso para encontrar y verificar un FWA:
1. Escanear los gaps entre las allocaciones de RAM gestionada
2. Filtrar regiones inseguras (MMIO, etc.)
3. Escribir un patrón temporal, leerlo y restaurar → verificación de que la página es utilizable

Una vez verificada, la página FWA sirve como workspace controlado invisible al SO.

### El flujo del ataque

```
1. Ligar el thread al CPU objetivo (la IDT es per-CPU)
2. Resolver: IDTR base → página física → PTE que mapea la IDT
3. Copiar la IDT completa a una página FWA verificada
4. Modificar en la copia: gate INT 2E → redirigir a payload
5. Cambiar transitoramente la PTE para que la IDT virtual 
   apunte a la FWA en lugar de a la página original
6. Disparar INT 2E
7. El payload corre en modo kernel:
   - PsGetCurrentProcess
   - PsReferencePrimaryToken
   - Token swap → SYSTEM
8. Restaurar la PTE original
9. Limpiar la página FWA
```

Desde el punto de vista de la CPU, el **IDTR base no cambia** — sigue apuntando a la misma dirección virtual. Lo que cambia es la traducción física: durante la ventana de ataque, esa dirección virtual resuelve a la FWA en lugar de a la IDT real.

### Por qué bypasea HVCI

HVCI vigila que **no se ejecute código no firmado**. Esta técnica no introduce código nuevo en el kernel — todo el payload (`PsGetCurrentProcess`, `memcpy`, etc.) son funciones nativas de ntoskrnl ya firmadas y cargadas. Lo que se modifica es únicamente un puntero en una tabla de datos. Por eso el check de integridad no salta.

---

## INT 2E: el mecanismo de despacho

`INT 2E` es el mecanismo legacy de transición usuario→kernel en x86, equivalente antiguo a `SYSCALL`. El handler `nt!KiSystemService` en ntoskrnl lo gestiona.

En x64 el path normal usa `SYSCALL + MSRs`, pero la IDT sigue presente y soporta `INT 2E`. La técnica lo usa como **puente de despacho** hacia una entrada de la SSDT — en concreto `NtSetQuotaInformationFile` — cuyo slot de tabla se redirige temporalmente al target real.

El resultado es una cadena que parece legítima en cada nivel de indirección.

---

## Implicaciones: qué cambia para el mundo del shellcode

Históricamente, HVCI + kCET eran el "game over" para la mayoría de técnicas de shellcode en modo kernel. Esta investigación cambia esa ecuación.

### El problema clásico que resolvían HVCI y kCET

Un shellcode tradicional en kernel implica:
1. Escribir código en una página ejecutable del kernel
2. Redirigir la ejecución hacia esa página

HVCI bloquea el paso 1 — no puedes marcar páginas como ejecutables sin firma. kCET bloquea el paso 2 — los saltos indirectos deben apuntar a destinos validados por shadow stack o endbr64.

Resultado: shellcode clásico muerto en Windows 11 hardened.

### Lo que abre esta técnica

La IDT hijacking con FWA elimina ambas restricciones sin violarlas directamente:

**No necesitas páginas ejecutables nuevas.** Todo el "payload" son funciones ya existentes en ntoskrnl — `PsGetCurrentProcess`, `memcpy`, `ObDereferenceObject`. El FWA solo contiene la tabla de datos modificada, no código.

**No saltas a código no validado.** El flujo pasa por `INT 2E → KiSystemService → SSDT slot → función nativa`. Cada salto apunta a código firmado. kCET no ve nada anómalo.

### Ejemplos concretos de lo que se puede hacer desde SYSTEM

Una vez ejecutado el token swap y teniendo SYSTEM, el abanico es total:

#### 1. Credential dumping sin tocar LSASS desde userland
```
SYSTEM → SeDebugPrivilege activo por defecto
       → OpenProcess(LSASS) sin restricciones de PPL
       → MiniDump / extracción directa de credenciales
```
El EDR ve un proceso con token SYSTEM abriendo LSASS — comportamiento "legítimo" para herramientas del sistema.

#### 2. Deshabilitar el EDR desde kernel
```
SYSTEM + contexto kernel → acceder al driver del EDR
                         → modificar sus callbacks (PsSetCreateProcessNotifyRoutine, etc.)
                         → el EDR queda ciego sin crashear
```
Esto es lo que hace herramientas como `Terminator` o `EDRSilencer`, pero desde kernel con permisos totales.

#### 3. Payload de ransomware con cifrado a nivel de volumen
```
SYSTEM → IoCreateFile con acceso raw al volumen
       → cifrar sectores directamente sin pasar por el filesystem
       → ni el AV ni el EDR ven operaciones de fichero individuales
```
El cifrado ocurre por debajo del filesystem driver, invisible para los filtros que monitorizan CreateFile/WriteFile.

#### 4. Persistencia en firmware / bootkits (con acceso físico a memoria)
```
FWA page access → acceso a memoria física fuera del mapa del SO
               → potencial modificación de regiones de UEFI si no están protegidas por Intel TXT/SMM
```
Este vector es más complejo y depende del hardware, pero la primitiva de memoria física que usan es el punto de entrada.

#### 5. Lateral movement transparente
```
SYSTEM + kernel → manipular tokens de otros procesos directamente
               → impersonation sin llamadas a Win32 visibles para el EDR
               → movimiento lateral sin credenciales en memoria userland
```

### El matiz importante: punto de entrada

Esta técnica **asume que ya tienes ejecución de código en el proceso** — no es un exploit de ejecución remota. Es una escalada de privilegios local. El atacante necesita:

- Código corriendo en el endpoint (phishing, vuln web, etc.)
- Acceso a la primitiva de memoria física (normalmente vía driver vulnerable — BYOVD)

El combo habitual en un ataque real sería:
```
Acceso inicial → BYOVD (driver vulnerable firmado)
              → primitiva de R/W en memoria física
              → IDT hijacking con FWA
              → SYSTEM
              → todo lo de arriba
```

Herramientas como `LOLDrivers` catalogan cientos de drivers firmados con vulnerabilidades que dan exactamente esa primitiva de memoria física.

---

## Implicaciones defensivas

Lo relevante desde el punto de vista de hardening:

- **No hay CVE** — no es un bug parcheable puntualmente. Es una consecuencia de la arquitectura x86 y del modelo de memoria física.
- **Los EDR que confían en HVCI como garantía absoluta** pueden tener un punto ciego aquí.
- **Detección**: buscar modificaciones transitorias en PTEs de páginas del kernel, anomalías en el mapeo físico de la IDT, o acceso a regiones FWA desde contexto kernel.

Microsoft ha publicado mitigaciones incrementales en este espacio con cada versión de Windows 11, pero la superficie de ataque en memoria física persiste mientras existan gaps en el mapa de RAM.

---

## Referencias

- [IDT Table Hijacking under VBS/HVCI/kCET in Windows 11 — ExploitPack](https://www.exploitpack.com/blogs/news/idt-table-hijacking-under-vbs-hvci-kcet-in-windows-11)
- [SSDT Hijacking — ExploitPack EP3](https://www.exploitpack.com)
- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Vol. 3A — Cap. 6 (IDT)](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Virtualization-Based Security — Microsoft Docs](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)
