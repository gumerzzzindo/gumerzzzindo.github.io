---
layout: single
title: "Hola Mundo"
date: 2024-10-17
categories: [blog]
tags: [presentacion]
excerpt: "Presentación del blog: análisis de malware, writeups de CTF y técnicas de pentesting. Primeros apuntes sobre enumeración SMB y reconocimiento."
permalink: /blog/hola-mundo/
---

Bienvenido. Este es mi blog sobre ciberseguridad, malware y hacking. Iré subiendo análisis, writeups de CTFs y apuntes técnicos.

---

## Primeros apuntes — Enumeración SMB

```bash
# Enumerar usuarios de dominio
rpcclient -U "" <ip> -N
> enumdomusers

# Fuerza bruta SMB
crackmapexec smb 172.17.0.2 -u macarena -p /usr/share/wordlists/rockyou.txt

# Listar recursos compartidos
smbclient -N -L //172.17.0.2

# Conectar a un recurso
smbclient -U macarena //172.17.0.2/macarena
```

---

## Conceptos de reconocimiento

| Técnica | Descripción |
|---|---|
| **Footprint** | Recolectar info pública (dominios, IPs, ubicación) |
| **Fingerprint pasivo** | Escucha pasiva con Wireshark |
| **Fingerprint activo** | Envío de paquetes (ej. Nmap scan) |
| **OSINT Framework** | Obtener info de fuentes abiertas |
| **Spidering** | Mapear una aplicación para conocer sus puntos de acceso |
