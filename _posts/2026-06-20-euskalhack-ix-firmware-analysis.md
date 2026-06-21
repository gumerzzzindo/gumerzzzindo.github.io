---
layout: single
title: "EuskalHack IX — Análisis de vulnerabilidades de firmware: emulación y periféricos virtuales"
date: 2026-06-20
permalink: /conference/euskalhack-ix-firmware-analysis/
excerpt: "Metodología de análisis de firmware sin hardware: extracción con Binwalk, reversing con Ghidra, emulación en QEMU con periféricos MMIO virtuales, fuzzing con Boofuzz y AFL++. Herramienta Perun."
categories: [conference]
tags: [euskalhack, euskalhack-ix, firmware, embedded, qemu, fuzzing, binwalk, ghidra, boofuzz, mmio]
toc: true
toc_sticky: true
series: "EuskalHack IX"
header:
  og_image: /assets/images/og-preview.png
---

> **TL;DR (EN):** Firmware vulnerability analysis without physical hardware: Binwalk extraction, Ghidra static analysis, QEMU emulation with virtual MMIO peripherals (the main challenge), Boofuzz for network fuzzing, AFL++ QEMU mode for binary fuzzing. Tool "Perun" automates partial emulation. Talk by Alex Agustín Maiza at EuskalHack IX, June 2026.

---

> **Ponente:** Alex Agustín Maiza · [Vicomtech](https://www.vicomtech.org) / [UPV/EHU](https://www.ehu.eus) · [LinkedIn](https://www.linkedin.com/in/alex-agust%C3%ADn-maiza-40122b350/)  
> **Congreso:** [EuskalHack IX](/conference/euskalhack-ix/) · Donostia, 19 de junio de 2026 · ES

---

## Contexto: sistemas embebidos

Los **sistemas embebidos** son computadores de propósito específico integrados en dispositivos físicos. Corren firmware propietario con recursos limitados y frecuentemente sin interfaces de usuario directas.

**Ejemplos:** routers, cámaras IP, videoporteros, ECUs de automóvil, PLCs industriales, impresoras, dispositivos médicos.

**ECU (Electronic Control Unit)** — unidades de control electrónicas en automoción. Un coche moderno tiene 70-100 ECUs. Firmware propietario sin fuentes disponibles.

**Vector de actualización maliciosa:** reemplazar el firmware legítimo por uno malicioso via OTA, USB, o canales de actualización comprometidos. Una vez instalado, el firmware malicioso tiene control total del hardware sin ninguna capa de seguridad del OS.

---

## El reto principal: no tener el hardware

Analizar firmware sin el dispositivo físico obliga a:
1. Extraer el firmware (web del fabricante, captura OTA, dump físico)
2. Emularlo en software para ejecutarlo, depurarlo y fuzzearlo
3. **Simular los periféricos que el firmware espera encontrar** ← el problema real

Sin emulación, el análisis queda limitado a reversing estático, que no revela bugs de runtime.

---

## QEMU — Emulación de sistemas completos

**QEMU** (Quick EMUlator) puede emular procesadores ARM, MIPS, PowerPC, RISC-V y otros en una máquina x86.

```bash
# Emular sistema ARM con firmware de router
qemu-system-arm \
  -M versatilepb \
  -kernel firmware.bin \
  -nographic \
  -append "console=ttyAMA0"

# Depuración con GDB remoto
qemu-system-arm [...] -s -S &      # -s: GDB server en :1234, -S: pausa al inicio
gdb-multiarch firmware.elf
(gdb) target remote :1234
(gdb) continue
```

---

## MMIO (Memory-Mapped I/O) — El problema central

En arquitecturas embebidas, los periféricos (UART, SPI, GPIO, ADC, timers) **no tienen puertos de E/S propios**. Se accede a ellos a través de **rangos de direcciones de memoria físicas**:

```
Mapa de memoria típico de SoC ARM:
0x00000000 - 0x0FFFFFFF  Flash ROM (firmware)
0x20000000 - 0x2FFFFFFF  RAM
0x40000000 - 0x4FFFFFFF  Periféricos (MMIO)
  0x40004000              UART0 base
    0x40004000              UART_DR   (Data Register)
    0x40004004              UART_RSR  (Status Register)
    0x40004018              UART_FR   (Flag Register)
  0x40013000              SPI1 base
  0x40020000              GPIO base
```

**El problema para QEMU:** cuando el firmware escribe en `0x40004000` para inicializar la UART, QEMU tiene que responder como lo haría el hardware real. Si no implementas el periférico virtual, QEMU devuelve 0 o genera una excepción → el firmware cuelga.

```python
# Ejemplo de periférico UART virtual en Python (via QEMU QOM)
class UARTPeripheral:
    UART_FR = 0x18   # Flag Register offset
    
    def read(self, offset):
        if offset == self.UART_FR:
            return 0x10  # TXFE=1: TX buffer vacío → firmware continua
        return 0
    
    def write(self, offset, value):
        if offset == 0x00:  # UART_DR: dato a enviar
            sys.stdout.write(chr(value))
```

---

## Herramienta: Perun

**Perun** es un framework para análisis automatizado de firmware:
- Análisis estático (extracción de cadenas, identificación de funciones)
- Emulación parcial (ejecutar funciones específicas sin emular el sistema completo)
- Identificación automática de periféricos MMIO necesarios

Útil cuando la emulación completa falla por periféricos desconocidos.

---

## Fuzzing de firmware

### Boofuzz — Fuzzing de protocolos de red

```python
from boofuzz import *

session = Session(
    target=Target(connection=TCPSocketConnection("192.168.1.1", 80))
)

s_initialize("HTTP GET")
s_string("GET", fuzzable=False)
s_delim(" ", fuzzable=False)
s_string("/cgi-bin/admin", fuzzable=True)  # fuzzear la ruta
s_delim(" ", fuzzable=False)
s_string("HTTP/1.1", fuzzable=False)

session.connect(s_get("HTTP GET"))
session.fuzz()
```

### AFL++ en modo QEMU — Fuzzing de binarios

```bash
# Fuzzing de binario ARM en QEMU sin código fuente
# -Q activa QEMU mode (instrumentación sin código fuente)
afl-fuzz -Q \
  -i corpus/ \
  -o findings/ \
  -- /bin/httpd @@
```

AFL++ con QEMU mode instrumenta el binario para medir **cobertura de código** y guiar el fuzzing hacia paths no explorados. Más potente que Boofuzz para bugs en código interno no expuesto en la interfaz de red.

---

## Flujo completo de análisis

```bash
# 1. EXTRACCIÓN
binwalk -e firmware.bin          # filesystem embebido
binwalk -A firmware.bin          # identificar arquitectura
strings firmware.bin | grep -iE "pass|key|secret|admin|root"

# 2. ANÁLISIS ESTÁTICO
# Cargar en Ghidra/IDA Pro para reversing
# Identificar funciones de red y parsers de input

# 3. EMULACIÓN
qemu-system-arm -M versatilepb -kernel fw.bin -nographic
# Implementar periféricos MMIO virtuales según el SoC

# 4. FUZZING
# Boofuzz → protocolos de red expuestos
# AFL++ QEMU → binarios internos
# Perun → análisis automatizado

# 5. ANÁLISIS DE ACTUALIZACIÓN
# ¿Tiene firma criptográfica? ¿Se verifica correctamente?
# ¿Está cifrado? ¿La clave está en el mismo firmware?
# ¿Acepta downgrade a versiones anteriores?
```

---

## Conceptos relacionados

### Herramientas de análisis

**Ghidra** — disassembler/decompiler de la NSA, gratuito:
- Soporte nativo ARM, MIPS, PowerPC, RISC-V, x86
- Decompila a C aproximado — mucho más rápido que leer ASM
- Scripting Python/Java para automatizar análisis

**angr** — análisis binario simbólico en Python:

```python
import angr
proj = angr.Project('/bin/httpd', auto_load_libs=False)
# Encontrar inputs que llevan a una función peligrosa (simbólicamente)
```

Puede encontrar automáticamente inputs que llegan a vulnerabilidades sin fuzzing exhaustivo.

### Secure Boot en embebidos

Verifica la firma criptográfica del firmware antes de cargarlo. **Debilidades comunes en IoT:**
- Clave pública de verificación hardcodeada en el propio firmware (extraíble con Binwalk)
- Secure Boot desactivado por defecto o saltable con comandos U-Boot
- Verificación de firma implementada incorrectamente (solo el header, no el firmware completo)

### TPM (Trusted Platform Module)

Chip hardware que almacena claves y verifica la integridad del firmware. Equivalente al HSM para dispositivos embebidos/PCs. Usado en Secure Boot robusto para que la clave de verificación no pueda extraerse.

### RTOS (Real-Time Operating System)

| RTOS | Uso típico | Licencia |
|------|-----------|---------|
| **FreeRTOS** | IoT, microcontroladores | Open source (MIT) |
| **VxWorks** | Aeroespacial, industrial | Propietario |
| **Zephyr** | IoT, wearables | Open source (Apache 2.0) |
| **ThreadX** | Médico, automoción | Propietario (Microsoft) |

Los RTOS frecuentemente **no tienen ASLR ni NX** por defecto → más fáciles de explotar, pero más difíciles de emular por sus requisitos de timing real.

### Interfaces físicas de extracción

| Interfaz | Qué da | Cómo encontrarla |
|----------|--------|-----------------|
| **JTAG** | Debug CPU completo: RAM, flash, breakpoints hardware | Pads en PCB, conector de 4-20 pines |
| **UART** | Consola serie: bootloader (U-Boot), shell de debug | Buscar 3-4 pads con 3.3V en reposo |
| **SPI/I2C flash** | Dump directo del chip de flash | Desolder el chip o usar clip SOIC |

Para encontrar UART: medir con multímetro los pads sin etiquetar en el PCB buscando nivel lógico 3.3V y señal variable durante el boot.

### Vectores de actualización maliciosa

| Vector | Condición de éxito |
|--------|------------------|
| OTA sin verificación de firma | MITM en la descarga o servidor comprometido |
| Firmware downgrade | El dispositivo acepta versiones anteriores con vulnerabilidades conocidas |
| Supply chain | Comprometer el servidor de actualizaciones → todos los dispositivos infectados |

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
| 6 | **Análisis de vulnerabilidades de firmware** ← estás aquí |
| 7 | [Minifilters: Owning the High (and Low) Ground](/conference/euskalhack-ix-minifilters-kernel/) |
