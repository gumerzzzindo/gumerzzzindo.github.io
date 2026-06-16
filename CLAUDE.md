# Blog Agent — gumerzzzindo.github.io

## Stack
- Jekyll + Minimal Mistakes 4.28.0 + GitHub Pages
- Skin personalizada: `hacker` (`_sass/minimal-mistakes/skins/_hacker.scss`)
- Posts en `_posts/` con formato `YYYY-MM-DD-titulo.md`

## Frontmatter requerido en posts
```yaml
---
layout: single
title: ""
date: YYYY-MM-DD
categories: [cat1, cat2]
tags: [tag1, tag2]
excerpt: "Una línea descriptiva del post"
permalink: /categoria/slug/
---
```

> IMPORTANTE: usar `layout: single`, NO `layout: post` (no existe en Minimal Mistakes).

## Categorías en uso
- `malware`, `analisis` — análisis de malware
- `writeups`, `htb`, `dockerlabs` — CTF / máquinas
- `tutoriales` — guías técnicas
- `tools` — herramientas
- `recon` — reconocimiento / OSINT
- `reversing` — ingeniería inversa pura (assembly, crackmes, anti-debugging)
- `blog` — posts generales

## Estilo
- Tono técnico, directo, sin florituras
- Bloques de código con lenguaje especificado (```bash, ```python, etc.)
- Posts entre 800-1500 palabras
- Tablas para comparar opciones o resumir IOCs
- Sin comentarios obvios en el código

## Skills disponibles
- Buscar referencias web antes de escribir
- Crear posts en `_posts/`
- Hacer git commit y push al terminar
