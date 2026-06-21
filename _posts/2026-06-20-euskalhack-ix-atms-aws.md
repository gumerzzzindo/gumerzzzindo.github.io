---
layout: single
title: "EuskalHack IX — ATMs conectados a AWS: ¿qué podría salir mal?"
date: 2026-06-20
permalink: /conference/euskalhack-ix-atms-aws/
excerpt: "Arquitectura XFS de cajeros automáticos, jackpotting (Ploutus/Tyupkin), ataques DMA sobre RAM, shimming vs EMV, y ATM conectado a AWS IoT Core con política IAM wildcard. Raquel Gálvez en EuskalHack IX."
categories: [conference]
tags: [euskalhack, euskalhack-ix, atm, aws, iot, xfs, jackpotting, dma, pci-dss, emv]
toc: true
toc_sticky: true
series: "EuskalHack IX"
header:
  og_image: /assets/images/og-preview.png
---

> **TL;DR (EN):** ATM security deep-dive: XFS middleware stack, jackpotting malware (Ploutus/Tyupkin), DMA attacks via PCIe, shimming can't clone EMV chips (unique Transaction Cryptogram per transaction). Modern vector: ATM connected to AWS IoT Core with wildcard IAM policy and disabled Kernel DMA Protection → direct RAM access. Talk by Raquel Gálvez at EuskalHack IX, June 2026.

---

> **Ponente:** Raquel Gálvez Farfán · X: [@Raquel_Galvez](https://x.com/Raquel_Galvez) *(cuenta privada)* · [LinkedIn](https://www.linkedin.com/in/raquel-galvez-farfan/) · (con mención a Héctor Cuevas)  
> **Congreso:** [EuskalHack IX](/conference/euskalhack-ix/) · Donostia, 19 de junio de 2026 · ES

---

## Arquitectura interna de un ATM

```
┌─────────────────────────────────────────────────┐
│                CPD / Procesador bancario         │
└─────────────────────┬───────────────────────────┘
                      │ TLS / mTLS
┌─────────────────────▼───────────────────────────┐
│              Windows (OS del ATM)                │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│    SPI (Service Provider Interface)              │
│    Drivers específicos: NCR / HS (Hyosung)      │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│    XFS (eXtensions for Financial Services)       │
│    API estándar ISO/CEN — abstrae el hardware    │
│    Mismo API en todos los fabricantes            │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│    Hardware: dispensador · lector · pinpad · NFC │
└─────────────────────────────────────────────────┘
```

**XFS** es el eslabón crítico: mismo API en todos los fabricantes (NCR, Diebold, Wincor, Hyosung). Resultado: **malware que habla XFS funciona en cualquier cajero**, independientemente del fabricante.

---

## Tipos de ATM por exposición física

| Tipo | Descripción | Riesgo físico |
|------|-------------|---------------|
| **Standalone** | Supermercados, gasolineras | Alto — sin seguridad propia |
| **Drive-through** | En autopistas para vehículos | Medio |
| **Through the wall** | Integrado en pared del banco | Bajo — acceso físico limitado |

---

## Taxonomía de ataques

### Robo de PIN

- **Shoulder surfing** — mirar por encima del hombro
- **Pin pad overlay / skimmer de teclado** — teclado falso que captura pulsaciones
- **Cámara espía** — enfocada al teclado desde ángulo calculado

### Robo de tarjeta

- **Card trapping** — dispositivo en la ranura que atrapa la tarjeta dentro del cajero
- **Distracción** — técnica social

### Robo de datos de tarjeta

**Skimming** — lector superpuesto en la ranura que copia la banda magnética:
- Track 1: nombre del titular
- **Track 2: PAN + fecha de caducidad + CVV de banda** ← el más valioso para clonar

**Shimming** — dispositivo ultradelgado dentro del lector de chip:

> ⚠️ **El shimming no puede clonar tarjetas EMV.** El chip genera un **Transaction Cryptogram** único por transacción usando criptografía asimétrica. Sin la clave privada del chip (que nunca sale del chip), el criptograma no es reutilizable.

**Sniff de paquetes** — captura del tráfico ATM ↔ procesador. Requiere compromiso de red o MITM físico.

### Cash trapping y ataques lógicos

**Cash trapping** — dispositivo en la bandeja que retiene físicamente los billetes. El ATM registra la transacción como exitosa, el cliente no recibe el dinero.

**Reversal attack (transacciones inversas)** — el ATM solicita reversión antes de dispensar. Si el procesador acepta, el dinero vuelve a la cuenta aunque el cajero dispense.

### Malware — Jackpotting

```
1. Acceso físico al PC del ATM (USB o abriendo la carcasa)
2. Instalar malware que habla XFS directamente con el dispensador
3. Enviar comando XFS de dispensación máxima
4. ATM escupe todos los billetes → money mule los recoge
```

**Malware ATM conocido:**

| Malware | Año | Método |
|---------|-----|--------|
| **Ploutus** | 2013 (México) | Primer malware ATM documentado. Activación via SMS o teclado externo |
| **Tyupkin** | 2014 | Acceso directo al dispensador via XFS. Activado a medianoche |
| **Ripper / Alice / ATMii** | 2016+ | Variantes modernas con módulos XFS intercambiables |

**Black box attack** — sin instalar malware en el OS: se corta el cable entre el controlador y el dispensador, se conecta un dispositivo propio (Raspberry Pi) que habla XFS directamente.

### Ataques físicos destructivos

```
- Ram raid / Smash & Grab — embestir con vehículo
- Pull out               — arrancar con cadenas / grúa
- Gas explosivo          — gas inflamable + detonación (muy común en UE)
- Explosivos sólidos     — menos frecuente
```

---

## ATM conectado a AWS — La demo

Stack cloud del cajero moderno:
- **AWS IoT Core** — autenticación mTLS con certificados entre ATM y cloud
- **MQTT** — protocolo publish/subscribe ligero para mensajería
- **OTA (Over the Air)** — actualizaciones remotas del software del ATM
- **IAM** (AWS Identity and Access Management) — control de permisos

**Vectores explotados en la demo:**

**1. Política IAM con wildcard `*`** — la política del dispositivo permitía todas las acciones sobre todos los recursos. Un certificado comprometido → acceso total.

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

**2. Kernel DMA Protection desactivada** — sin IOMMU/VT-d activo, un dispositivo PCIe conectado al ATM puede leer/escribir RAM directamente sin pasar por la CPU:

```
Atacante conecta dispositivo PCIe → bus PCIe → RAM del ATM
                                               ↑ sin CPU ni OS
Puede: extraer claves de cifrado · modificar código en RAM · leer PINs en memoria
```

**Comparativa de protección DMA:**

| OS | Protección DMA |
|----|----------------|
| Windows XP / 7 | Sin protección — vulnerable por defecto |
| Windows 10+ | Kernel DMA Protection (VT-d/IOMMU) — requiere configuración correcta |

---

## Conceptos relacionados

### PCI DSS (Payment Card Industry Data Security Standard)

Estándar de seguridad obligatorio para cualquier entidad que procese datos de tarjetas. Los ATMs deben cumplirlo, incluyendo la parte cloud. Requisitos clave: TLS 1.2+, HSM certificado, segmentación de red, log y auditoría de transacciones.

### EMV (Europay, Mastercard, Visa — Chip & PIN)

El chip genera un **Transaction Cryptogram** único para cada transacción. Sin la clave privada del chip, no se puede generar un criptograma válido → el shimming no sirve para transacciones con chip obligatorio.

### HSM en ATMs

Los ATMs tienen su propio HSM en el pinpad (EPP — Encrypting PIN Pad). El PIN se cifra dentro del EPP hardware antes de salir hacia el cable — nunca viaja en claro, ni siquiera hacia el OS del ATM.

### Segmentación de red

Los ATMs deberían estar en una VLAN aislada con acceso únicamente al procesador bancario (puerto 443/8443 hacia el CPD). En la práctica muchos están en redes planas — si comprometes un cajero, ves toda la LAN del local.

### SWIFT y el Bangladesh Bank Heist

**SWIFT** es la red global de mensajería interbancaria. En el ataque al **Banco de Bangladesh (2016)**, comprometiendo el software cliente SWIFT del banco, los atacantes enviaron órdenes de transferencia falsas por 951 M$ — consiguieron 81 M$ antes de que se detectara.

### AWS IoT Greengrass

Amplía AWS IoT Core ejecutando funciones Lambda localmente en el dispositivo cuando no hay conectividad. Si comprometes el agente Greengrass del ATM, tienes ejecución de código con sus permisos.

### Malware ATM y defensa

```
Defensa contra jackpotting:
- Application Whitelisting (solo los ejecutables firmados pueden correr)
- Deshabilitar puertos USB físicos
- Monitorización de comandos XFS inusuales
- BIOS password + Secure Boot activo
- Kernel DMA Protection habilitada
```

---

---

## EuskalHack IX — Serie completa

| # | Post |
|---|------|
| Índice | [Notas técnicas — todas las charlas](/conference/euskalhack-ix/) |
| 1 | [Agentic AI Supremacy — Is your AI a double-agent?](/conference/euskalhack-ix-agentic-ai/) |
| 2 | [Insiders: detección de amenazas internas](/conference/euskalhack-ix-insiders-ueba/) |
| 3 | [Hackeando videoporteros — root sin llamar al timbre](/conference/euskalhack-ix-videoportero-iot/) |
| 4 | **ATMs conectados a AWS: ¿qué podría salir mal?** ← estás aquí |
| 5 | [Radar real con ESP32 por menos de 15€](/conference/euskalhack-ix-radar-esp32/) |
| 6 | [Análisis de vulnerabilidades de firmware](/conference/euskalhack-ix-firmware-analysis/) |
| 7 | [Minifilters: Owning the High (and Low) Ground](/conference/euskalhack-ix-minifilters-kernel/) |
