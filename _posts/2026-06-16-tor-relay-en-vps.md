---
layout: single
title: "Montar un relay de Tor en un VPS: para qué sirve, qué se gana y si estás ayudando al crimen"
date: 2026-06-16
categories: [tutoriales, tools]
tags: [tor, relay, vps, privacidad, anonimato, red-tor, legal]
excerpt: "Qué tipos de relay existen, cómo montar uno en un VPS, qué ganas realmente (spoiler: nada económico) y qué dice la ley sobre operarlos."
permalink: /tutoriales/tor-relay-vps/
---

Cada vez que alguien dice "voy a montar un nodo de Tor" surgen las mismas tres preguntas: ¿qué gano yo con esto?, ¿por qué debería molestarme? y la que casi nadie hace en voz alta: ¿no estaré ayudando a que alguien venda drogas o distribuya material ilegal? Vamos a desmontar las tres con datos, no con suposiciones.

## Qué es un relay y qué tipos hay

La red Tor enruta el tráfico a través de tres saltos cifrados en capas (de ahí "onion routing"). Cada salto solo conoce el nodo anterior y el siguiente, nunca el origen y el destino a la vez. Los relays son los servidores que forman esos saltos:

| Tipo | Función | Ve tu IP de origen | Ve el destino final | Riesgo legal |
|---|---|---|---|---|
| **Guard** | Primer salto, el cliente se conecta directamente a él | Sí (la del usuario) | No | Muy bajo |
| **Middle** | Salto intermedio, solo reenvía tráfico cifrado | No | No | Prácticamente nulo |
| **Exit** | Último salto, saca el tráfico a la internet "normal" | No | Sí (aparece como origen del tráfico) | Alto |
| **Bridge** | Relay no listado públicamente, para esquivar censura | Sí | No | Bajo |

Un relay normal (guard/middle) nunca expone tu IP como origen de tráfico hacia destinos externos: tu servidor reenvía paquetes cifrados que no puede leer. El exit relay es el único caso donde tu IP aparece literalmente como la fuente del tráfico que sale a internet — ahí está toda la diferencia legal y práctica.

## Por qué un VPS y no tu casa

Un VPS te da IP estática, ancho de banda simétrico decente y uptime que tu router doméstico no va a darte. Además, separa tu identidad/IP residencial del relay, lo cual importa especialmente si algún día decides correr un exit (que, como se ve abajo, no deberías hacer desde casa bajo ningún concepto).

Requisitos mínimos recomendados por el propio Tor Project:

- **Ancho de banda**: al menos 10 Mbit/s, idealmente 16 Mbit/s simétricos. Por debajo de eso, mejor monta un bridge con `obfs4`.
- **RAM**: 512 MB para un middle relay modesto, 1-2 GB si quieres tráfico serio.
- **Tor actualizado**: usa el repo oficial de Tor Project, no el de la distro (suele ir varias versiones por detrás).

## Configuración básica (Debian/Ubuntu)

```bash
echo "deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main" | sudo tee /etc/apt/sources.list.d/tor.list
curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | sudo tee /usr/share/keyrings/deb.torproject.org-keyring.gpg
sudo apt update && sudo apt install tor
```

En `/etc/tor/torrc`:

```
Nickname MiRelayVPS
ContactInfo tu-email-o-clave-pgp@dominio.tld
ORPort 9001
ExitRelay 0
SocksPort 0
RelayBandwidthRate 2 MB
RelayBandwidthBurst 4 MB
```

`ExitRelay 0` es el valor por defecto: con esta config corres un relay (guard/middle) sin tráfico de salida a internet. `ContactInfo` es importante — si tu proveedor de VPS recibe una queja, quieres que te llegue a ti antes de que te suspendan la cuenta sin avisar. Reinicia el servicio y al cabo de unas horas tu relay debería aparecer en [Tor Metrics](https://metrics.torproject.org/rs.html) con los flags `Running`, `Valid` y, con el tiempo, `Guard`/`Fast`/`Stable` (se asignan automáticamente según el comportamiento observado, no hay que solicitarlos).

## Qué se gana realmente

Nada económico. No hay "karma", ni créditos, ni ningún sistema de recompensa — Tor Project lo deja claro: es contribución voluntaria, punto. Lo que sí ganas:

- **Aprendizaje real de redes y criptografía aplicada** — entiendes onion routing, gestión de ancho de banda, hardening de un servicio expuesto a internet 24/7.
- **Reputación dentro de la comunidad** si publicas tus métricas/uptime.
- **Diversidad de la red** — cuantos más relays haya en más países y autonomous systems distintos, más difícil es para un atacante (estatal o no) correlacionar tráfico observando solo un punto de la red.

Lo que **no** ganas, y es un mito habitual: correr un relay no anonimiza más tu propio tráfico. Eso lo consigue usar Tor Browser, no operar infraestructura para otros.

## Por qué merece la pena contribuir

La red Tor depende de voluntarios. Más relays significa más capacidad, menos latencia y, sobre todo, más resiliencia frente a censura — para periodistas en regímenes represivos, activistas, ONGs, e investigadores de seguridad que necesitan ocultar el origen de sus consultas (sí, también para esto último). Cada relay middle que añades diluye la concentración de la red en pocos operadores, que es justo el escenario que un adversario con capacidad de vigilancia global quiere explotar.

## La pregunta incómoda: ¿estoy ayudando al crimen?

Vamos con datos, no con sensación de culpa:

- **Ningún operador ha sido condenado en EE. UU. por el simple hecho de correr un relay de Tor**, exit incluido, según la [Legal FAQ de la EFF para operadores de relay](https://www.eff.org/pages/legal-faq-tor-relay-operators). La propia EFF opera relays middle precisamente porque está convencida de que quien los opera no debería ser responsable del tráfico que pasa por ellos.
- Si corres un **middle o guard relay**, tu IP nunca aparece como origen de tráfico hacia ningún destino externo. Legalmente es equivalente a operar un router de tránsito — no puedes ver ni eres responsable del contenido. Riesgo prácticamente nulo.
- El matiz está en los **exit relays**: ahí tu IP sí aparece como la fuente aparente de cualquier tráfico que salga por él, y es estadísticamente inevitable que en algún momento ese tráfico incluya algo ilegal — igual que un ISP grande verá tráfico ilegal cruzando su red tarde o temprano. La [propia documentación de Tor Project](https://support.torproject.org/relays/legal-and-abuse/exit-relay-expectations/) advierte que esto puede generar quejas de abuso o consultas de las fuerzas de seguridad, no una imputación automática.
- Recomendación tanto de Tor Project como de la EFF: **no corras un exit relay desde casa**. Los operadores ideales de exits son universidades, bibliotecas, hackerspaces u organizaciones con capacidad legal para gestionar quejas — no un VPS personal a tu nombre.
- Importante: en EE. UU. (y por extensión en jurisdicciones con legislación similar de interceptación de comunicaciones), monitorizar, registrar o divulgar el tráfico que pasa por tu relay puede generarte responsabilidad civil o penal a *ti*. No mires logs de tráfico de terceros — ni lo necesitas ni te conviene.

Si te preocupa la exposición legal, la respuesta práctica es simple: empieza por un relay middle. Es donde está el 90% del valor para la red y básicamente cero riesgo. El exit relay es una decisión seria, con matices legales reales, que se toma con conocimiento de causa y, si puede ser, no desde tu propio nombre.

## Resumen

| Acción | Esfuerzo | Riesgo legal | Aporte a la red |
|---|---|---|---|
| Relay middle/guard en VPS | Bajo | Casi nulo | Alto |
| Bridge con obfs4 | Bajo | Bajo | Alto en países con censura activa |
| Exit relay personal | Medio-alto | Real, gestionable | Muy alto, pero mejor vía institución |

Montar un relay no te convierte en cómplice de nada por defecto. Te convierte en una pieza más de una red descentralizada que, estadísticamente, se usa muchísimo más para periodismo, privacidad básica y evasión de censura que para delitos — exactamente igual que internet en general.

**Fuentes**: [EFF — Legal FAQ for Tor Relay Operators](https://www.eff.org/pages/legal-faq-tor-relay-operators), [Tor Project — What to expect when running an exit relay](https://support.torproject.org/relays/legal-and-abuse/exit-relay-expectations/), [Tor Project — Relay Operations Guide](https://community.torproject.org/relay/).
