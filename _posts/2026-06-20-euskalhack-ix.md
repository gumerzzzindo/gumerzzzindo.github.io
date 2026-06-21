---
layout: single
title: "EuskalHack Security Congress IX — Notas técnicas"
date: 2026-06-20
permalink: /conference/euskalhack-ix/
excerpt: "Notas técnicas del EuskalHack IX (Donostia, junio 2026): IA agéntica, insiders, IoT, cajeros en AWS, radar ESP32, firmware y evasión de EDR con minifilters."
categories: [conference]
tags: [euskalhack, euskalhack-ix, donostia, "2026", offensive-security, kernel, iot, ai, atm, radar, firmware]
toc: true
toc_sticky: true
series: "EuskalHack IX"
---

> **TL;DR (EN):** Personal technical notes from EuskalHack Security Congress IX (Donostia, June 19–20 2026). Seven talks covering agentic AI attacks, insider threat detection, IoT exploitation, ATM/AWS security, radar with ESP32, firmware analysis, and Windows kernel minifilter evasion. Full write-up per talk below.

---

EuskalHack es el congreso de seguridad informática organizado por la asociación homónima en Euskadi. La IX edición reunió investigadores de toda España con charlas técnicas de primer nivel. Estas son mis notas personales enriquecidas tras las charlas del **viernes 19 de junio**.

## Índice de charlas

| # | Charla | Ponente | Perfiles | Post |
|---|--------|---------|---------|------|
| 1 | The Agentic AI Supremacy — Is your AI a double-agent? | Roger Sanz · Plain Concepts | [GH](https://github.com/rogersanz) · [LI](https://www.linkedin.com/in/rogersanz/) | [→ Leer](/conference/euskalhack-ix-agentic-ai/) |
| 2 | Insiders: detección de amenazas internas | Rubén Darío Castillo · Palo Alto Networks | [X](https://x.com/Rubendcastillo) | [→ Leer](/conference/euskalhack-ix-insiders-ueba/) |
| 3 | Hackeando videoporteros: acceso root sin llamar al timbre | Jose Luis Verdeguer | [GH](https://github.com/Pepelux) · [X](https://x.com/pepeluxx) · [LI](https://www.linkedin.com/in/pepelux/) | [→ Leer](/conference/euskalhack-ix-videoportero-iot/) |
| 4 | ATMs conectados a AWS: ¿qué podría salir mal? | Raquel Gálvez Farfán | [X](https://x.com/Raquel_Galvez) *(privada)* · [LI](https://www.linkedin.com/in/raquel-galvez-farfan/) | [→ Leer](/conference/euskalhack-ix-atms-aws/) |
| 5 | Construyendo un radar real con un ESP32 | Pedro Candel (s4ur0n) · CS3 GROUP | [GH](https://github.com/PedroCandel) · [X](https://x.com/NN2ed_s4ur0n) | [→ Leer](/conference/euskalhack-ix-radar-esp32/) |
| 6 | Análisis de vulnerabilidades de firmware | Alex Agustín Maiza · Vicomtech / EHU | [LI](https://www.linkedin.com/in/alex-agust%C3%ADn-maiza-40122b350/) | [→ Leer](/conference/euskalhack-ix-firmware-analysis/) |
| 7 | Minifilters: Owning the High (and Low) Ground | Kurosh Dabbagh · BlackArrow / Tarlogic | [GH](https://github.com/kudaes) · [X](https://x.com/_Kudaes_) · [LI](https://www.linkedin.com/in/kuroshda/) | [→ Leer](/conference/euskalhack-ix-minifilters-kernel/) |

---

## Resumen ejecutivo

### 🤖 Agentic AI — Roger Sanz
Los sistemas de IA agénticos (capaces de actuar de forma autónoma, encadenar herramientas y mantener memoria) abren una superficie de ataque completamente nueva. La charla cubrió ataques como **Memory Injection (MINJA)**, **RAG Poison**, **Agent-in-the-Middle** y **Poisoned Skills** en marketplaces de agentes. El modelo mental clave: un agente con acceso a herramientas y memoria persistente tiene la misma superficie de ataque que un sistema distribuido, más prompt injection como vector universal.

### 👤 Insiders — Rubén Darío Castillo (Palo Alto)
Detección de amenazas internas con **CORTEX XSIAM**. Los tres pilares: complejidad (anomalías respecto a baseline), visibilidad (endpoints + red + identidad) e identidad (quién hace qué y cuándo). Técnicas de ataque insider: **GraalVM abuse**, **timestomping**, **LNK/Jumplist** para persistencia. La defensa pasa por UEBA + PAM + DLP + Canary Tokens.

### 🔌 IoT Videoportero — Jose Luis Verdeguer
Root completo sobre un videoportero Grandstream explotando un **buffer overflow en strcpy()** en el servidor web **GoAhead** (CVE-2020-5763). La arquitectura ARM64 con ASLR requirió construir un ROP chain usando ROPgadget + `dup2()` para redirigir stdin/stdout al socket → reverse shell. Las credenciales en claro aparecieron en `/etc/sys_default_user`.

### 💳 ATMs on AWS — Raquel Gálvez
Arquitectura de cajeros: `CPD → Windows → SPI → XFS → hardware`. El stack XFS es el mismo en todos los fabricantes → malware portable (Ploutus, Tyupkin). Vector moderno: ATM conectado a AWS IoT Core con política IAM `*` y **Kernel DMA Protection desactivada** → DMA attack directo sobre RAM. Shimming puede copiar banda magnética pero **no puede clonar chips EMV** (criptograma único por transacción).

### 📡 Radar ESP32 — Pedro Candel (cs3stec)
Construcción de un velocímetro funcional con módulo radar **HLK-LD2451** (24 GHz, ~5€) conectado por UART al ESP32. La física: efecto Doppler para velocidad, FMCW para velocidad + distancia simultáneas. Procesado de señal: FFT → Range-Doppler Map → CFAR para detección. Filtro de Kalman para suavizado. La Guardia Civil usa banda **Ka (26.5-40 GHz)**.

### 🔧 Firmware Analysis — Alex Agustín Maiza
Metodología de análisis sin hardware físico: extracción (Binwalk/UART dump) → análisis estático (Ghidra) → emulación en **QEMU** con periféricos MMIO virtuales → fuzzing con **Boofuzz** o AFL++ QEMU mode. La herramienta **Perun** automatiza análisis + emulación parcial. El reto principal en QEMU: implementar los periféricos que el firmware espera (MMIO).

### 🛡️ Minifilters — Kurosh Dabbagh (BlackArrow / Tarlogic · [@kudaes](https://github.com/kudaes))
El ataque más sofisticado del congreso. Usando **cldflt.sys** (Cloud Files) y **bindflt.sys** (altitud ~409900, por encima de los AV en ~320000), se monta una doble hidratación: primera entrega de goodware al EDR para que lo marque como limpio, segunda hidratación con malware referenciado solo por **FRN** (File Reference Number, sin ruta). `NtCreateProcessEx` con FRN bypasea las detecciones path-based de msmpeng.exe. Sin parchear kernel, sin tocar SSDT.

---

*Notas personales enriquecidas post-evento. Los errores de interpretación son míos.*
