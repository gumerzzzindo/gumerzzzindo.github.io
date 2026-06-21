---
layout: single
title: "EuskalHack IX — Construyendo un radar real con ESP32: velocidad y distancia por menos de 15€"
date: 2026-06-20
permalink: /conference/euskalhack-ix-radar-esp32/
excerpt: "Radar funcional con HLK-LD2451 (24 GHz, 5€) + ESP32 via UART. Física: Doppler + FMCW. Procesado de señal: FFT, Range-Doppler Map, CFAR, filtro de Kalman. La Guardia Civil usa banda Ka (26.5-40 GHz)."
categories: [conference]
tags: [euskalhack, euskalhack-ix, esp32, radar, doppler, fmcw, sdr, dsp, hardware, rf]
toc: true
toc_sticky: true
series: "EuskalHack IX"
header:
  og_image: /assets/images/og-preview.png
---

> **TL;DR (EN):** Building a functional speed radar with HLK-LD2451 module (24 GHz, ~€5) connected via UART to an ESP32 — total cost under €15. Core signal processing: FFT for distance (FMCW beat frequency), Range-Doppler Map, CFAR detection, Kalman filter for smoothing. Traffic police in Spain use Ka band (26.5–40 GHz). Talk by Pedro Candel (s4ur0n) at EuskalHack IX, June 2026.

---

> **Ponente:** Pedro Candel (s4ur0n) · [CS3 GROUP](https://cs3group.es) · X: [@NN2ed_s4ur0n](https://x.com/NN2ed_s4ur0n) · GitHub: [@PedroCandel](https://github.com/PedroCandel)  
> **Congreso:** [EuskalHack IX](/conference/euskalhack-ix/) · Donostia, 19 de junio de 2026 · ES

---

## Fundamentos físicos: el efecto Doppler

El efecto Doppler es la variación de frecuencia percibida cuando la fuente o el receptor están en movimiento relativo.

```
Objeto en reposo:    f_emitida == f_recibida
Objeto acercándose:  f_recibida > f_emitida   (compresión)
Objeto alejándose:   f_recibida < f_emitida   (expansión)

Velocidad = (Δf × λ) / 2
donde λ = longitud de onda, Δf = diferencia de frecuencia
```

La diferencia de frecuencia entre la señal emitida y la reflejada es directamente proporcional a la velocidad del objeto.

---

## Tipos de radar de velocimetría

### CW (Continuous Wave)

- Emite una señal de frecuencia constante de forma continua
- Mide únicamente **velocidad** (por Doppler)
- **No puede medir distancia** — no hay referencia temporal
- Simple y barato

### FMCW (Frequency Modulated Continuous Wave)

- Emite señales con frecuencia que varía linealmente en el tiempo (**chirps**)
- La diferencia de frecuencia entre señal emitida y reflejada da **distancia**
- El desplazamiento Doppler da **velocidad**
- Mide distancia Y velocidad **simultáneamente**
- Estándar en radar moderno (tráfico, ADAS de coches, etc.)

```
FMCW chirp — frecuencia vs tiempo:

Frecuencia
    ↑     /|    /|    /|
    |    / |   / |   / |
    |   /  |  /  |  /  |
    |  /   | /   | /   |
    └──────────────────────→ Tiempo

La distancia al objeto = diferencia de frecuencia entre señal emitida y reflejada
```

---

## SDR (Software Defined Radio)

Radio implementada por software en lugar de hardware dedicado. Con hardware SDR y software libre puedes analizar señales de radar:

> ⚠️ **Limitación importante:** Un dongle RTL-SDR (~10 €) solo llega hasta ~1.766 GHz. **No puede recibir señales de 24 GHz ni de banda Ka (26.5-40 GHz)**. Para monitorizar radares de tráfico necesitas hardware específico: un LNB de satélite como downconverter + RTL-SDR (que desplaza Ka a L-band), o equipos SDR de rango alto (HackRF, USRP) con mezcladores externos.

Lo que sí puedes hacer con RTL-SDR para aprender:
- Analizar señales de radar de corto alcance en 24 GHz ISM con hardware adicional
- Medir espectro en frecuencias bajas (FM, ADS-B, GSM)

```bash
# Escuchar L-band (señal Ka downconvertida por LNB) con RTL-SDR
rtl_sdr -f 1.5e9 -s 2.4e6 - | gqrx
```

Software: **GNU Radio**, **Gqrx**, **SDRAngel**, **SDR#** (Windows).

---

## Bandas de frecuencia en España

| Banda | Rango | Uso principal |
|-------|-------|---------------|
| **K** | 18-27 GHz | Algunos radares de tráfico antiguos |
| **Ka** | 26.5-40 GHz | **Guardia Civil y DGT** — radares de velocidad actuales |
| **24 GHz** | ~24.125 GHz | Módulos radar corto alcance (HLK-LD2451, ADAS) |
| **77 GHz** | 76-81 GHz | Radar ADAS de automoción moderna (mayor precisión) |

Los detectores de radar comerciales detectan principalmente **banda Ka**. Los radares láser (LIDAR) son indetectables con detectores convencionales de RF.

---

## Taxonomía de radares de tráfico

- **Fijos** — instalados en postes o sobre la calzada. Miden en un punto fijo.
- **Móviles** — sobre trípode o en vehículo patrulla estacionado. Reubicables.
- **Cinemáticos** — miden mientras el coche patrulla está en movimiento. Requieren corrección por la velocidad propia del patrulla.
- **De sección** — velocidad media entre dos puntos. Más difíciles de "engañar" decelerando al ver el radar.

**SINVCA** — Sistema Integrado de Gestión y Control de la DGT. Integra datos de todos los radares fijos y procesa multas automáticamente.

---

## Implementación: HLK-LD2451 + ESP32

### Módulo HLK-LD2451

- **Fabricante:** Hi-Link (China)
- **Frecuencia:** 24 GHz (banda ISM, sin licencia en la UE para potencia baja)
- **Precio:** ~5 € — el módulo radar funcional más barato del mercado
- **Capacidades:** presencia, velocidad y dirección del movimiento
- **Interfaz:** UART

### Conexión con ESP32

```
HLK-LD2451 (UART TX) ──────→ ESP32 (UART RX GPIO16)
HLK-LD2451 (UART RX) ←────── ESP32 (UART TX GPIO17)
HLK-LD2451 (VCC)     ──────── 3.3V del ESP32
HLK-LD2451 (GND)     ──────── GND del ESP32
```

El ESP32 recibe velocidad, distancia estimada y dirección vía UART, aplica filtro de Kalman y publica vía WiFi/MQTT.

Coste total del proyecto: **< 15 €** (ESP32 + HLK-LD2451 + pantalla OLED).

---

## Procesado de señal

### FFT (Fast Fourier Transform)

Transforma la señal del dominio temporal al dominio frecuencial. En FMCW:

```
señal IF (mezcla emitida × recibida) → FFT → espectro → pico en f ∝ distancia
```

### Range-Doppler Map

Matriz 2D obtenida con dos FFTs:

```
Chirp 1 → Range FFT → fila 1
Chirp 2 → Range FFT → fila 2
...
Chirps N → Range FFT → fila N
                       ↓
            Doppler FFT por columna
                       ↓
             Range-Doppler Map 2D

Eje X: distancia (metros)
Eje Y: velocidad (m/s)
Cada celda: energía reflejada para esa (distancia, velocidad)
```

### CFAR (Constant False Alarm Rate)

Algoritmo de detección que compara la energía de cada celda con la energía media de sus vecinas. Si supera el umbral adaptativo → "hay un objeto". Sin CFAR, el ruido generaría miles de falsas detecciones.

### Filtro de Kalman

Estimación óptima para sistemas con ruido. Combina predicción física y medición del radar:

```
Estado estimado(t) = Kalman( Estado(t-1), Medición(t), Ruido_modelo, Ruido_medición )

Salida: posición y velocidad suavizadas, con predicción entre mediciones
```

Estándar en radar, GPS, navegación inercial, guiado de misiles.

---

## Regulación

**ETSI EN 302 288** — Norma europea para módulos radar 24 GHz. El HLK-LD2451 puede usarse sin licencia en la UE para aplicaciones de detección de movimiento dentro de los límites de potencia establecidos.

### Detectores y jammers

| Dispositivo | Legalidad en España | Efectividad |
|-------------|--------------------|-|
| Detector de radar (Ka) | Posesión legal, **uso en circulación ilegal** | Alta contra CW/FMCW Ka |
| Jammer de radar | **Ilegal** (emite RF sin licencia) | Alta, pero el patrulla detecta la ausencia de señal |
| LIDAR jammer activo | **Ilegal** | Variable |

---

## Radar vs LIDAR

| | Radar (Ka/24 GHz) | LIDAR (Láser) |
|---|---|---|
| Condiciones adversas (lluvia, niebla) | Bien | Peor |
| Precisión angular | Baja | Alta |
| Medición de velocidad | Nativa (Doppler) | Requiere múltiples pulsos |
| Detectable con SDR | Sí | No (infrarrojo, no RF) |
| Coste | Bajo | Alto |

---

## EuskalHack IX — Serie completa

| # | Post |
|---|------|
| Índice | [Notas técnicas — todas las charlas](/conference/euskalhack-ix/) |
| 1 | [Agentic AI Supremacy — Is your AI a double-agent?](/conference/euskalhack-ix-agentic-ai/) |
| 2 | [Insiders: detección de amenazas internas](/conference/euskalhack-ix-insiders-ueba/) |
| 3 | [Hackeando videoporteros — root sin llamar al timbre](/conference/euskalhack-ix-videoportero-iot/) |
| 4 | [ATMs conectados a AWS: ¿qué podría salir mal?](/conference/euskalhack-ix-atms-aws/) |
| 5 | **Radar real con ESP32 por menos de 15€** ← estás aquí |
| 6 | [Análisis de vulnerabilidades de firmware](/conference/euskalhack-ix-firmware-analysis/) |
| 7 | [Minifilters: Owning the High (and Low) Ground](/conference/euskalhack-ix-minifilters-kernel/) |
