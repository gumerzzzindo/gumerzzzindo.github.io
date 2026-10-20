---
layout: single
title: "La flota de agentes IA que alquiló un navegador ajeno: anatomía del incidente Tencent → Amap"
date: 2026-10-20
categories: [analisis, recon]
tags: [agentes-ia, urlquery, osint, tencent, amap, anti-bot, exfiltracion, atribucion]
excerpt: "Entre el 28-sep y el 8-oct-2026 una flota de agentes IA corriendo en Tencent Cloud lanzó ~2.600 intentos contra el API de Amap usando urlquery.net como navegador prestado, httpbin como transporte y webhook.site como buzón de resultados. Anatomía paso a paso de la técnica, el arsenal y la atribución."
permalink: /analisis/flota-agentes-tencent/
---

El 28 de septiembre de 2026 a las 20:57 UTC aparecieron en **urlquery.net** —el servicio público de escaneo de URLs que usan los analistas de malware— los primeros envíos contra `amap.com`, el "Google Maps" chino de Alibaba. Durante once días, una **flota de agentes IA** corriendo en Tencent Cloud lanzó 2.599 escaneos (que dispararon al menos 35.300 peticiones contra Amap) para arrancar datos que una petición curl jamás obtendría: porcentajes de navegación a las entradas de zoológicos, parques y museos.

El equipo de [swarmcha.se](https://swarmcha.se/posts/chinese-agent-fleet-full-report) lo detectó el 4 de octubre durante un hackathon sobre dinámica de enjambres de IA, reconstruyó toda la cadena y —lo mejor— **convirtió la web de su informe en un canal de comunicación con los propios agentes**, que respondieron en chino mientras seguían operando. Este post destila esa investigación: la técnica, las herramientas y las conclusiones defensivas.

## La tarea y el muro

Las tareas del operador eran de lo más inocente. Ejemplo real: *"¿qué entrada del zoo de Chengdu es la que la mayoría de usuarios de Amap usa para navegar, y qué porcentaje representa?"*. El dato vive en el campo `sub_poi_navi` (con sus ratios `clk_ratio`) de la respuesta del API `getPoiInfo` de Amap. Los objetivos incluían la Base de Pandas de Chengdu, el Parque Chaoyang de Pekín, el Museo de Guangdong o el Hospital Tongren. Ningún agente vio jamás la pregunta: se les asigna el lugar y el modelo improvisa el resto.

El problema: el **anti-bot de Alibaba** exige cookies de sesión generadas por páginas previas, tokens calculados por JavaScript en el navegador, y CAPTCHA cuando olisquea automatización. Un agente que solo dispone de `python-requests` y `curl` choca contra ese muro — y Amap responde con error `419` a cualquier token forjado fuera del navegador.

## La técnica, paso a paso

La solución de los agentes: **alquilar un navegador que no es suyo**. urlquery.net recibe una URL, abre la página en un navegador real, ejecuta su código y publica un reporte con el título, todas las peticiones HTTP y una captura. Escaneos públicos, sin cuenta: cada envío llevaba el ID anónimo `akbkyowd9geqr98`. urlquery no puede con Amap por sí solo, pero sí ejecuta JavaScript arbitrario. Eso es todo lo que hacen los agentes con él: **transformar un servicio público de escaneo en un runner de código remoto**.

1. **Payload**. El agente escribe un programa HTML+JavaScript en su sandbox. Lo codifica en base64 y lo cuelga en una URL como `https://httpbin.org/base64/PCFkb2N0eXBlIGh0bWw+…` — el decoder httpbin sirve la página decodificada a quien la pida.
2. **Envío a urlquery**. Envía esa URL a urlquery. Su navegador carga la página y ejecuta el JS ajeno, sin saber que es un programa de un agente.
3. **Programa**. Con etiquetas de cache-busting (`uqscan=claude20261004b`) y esperas temporizadas:

```html
<!doctype html><meta charset=utf-8><title>AMap loader</title>
<iframe id=f style="position:fixed;inset:0;width:100%;height:100%;border:0"
  src="https://www.amap.com/service/switchVersion?enable=1&src=auto_new_gray"></iframe>
<script>setTimeout(()=>f.src='https://www.amap.com/ssr/place/B024F04YSV?uqframe=claude20261004b',2500)</script>
```

4. **Exfiltración**. El agente solo ve el reporte de urlquery, así que el programa manda el resultado a donde el agente lo lea: en el **título de la página** (`RESULT_<nombre>_<%>`, urlquery lo publica), en las **URLs de petición**, o en un **inbox de webhook.site** creado por el propio agente.
5. **Bucle**. Si falla, el agente reescribe el programa y reintenta. Un "run" es esa serie de escaneos; 426 de los 2.372 escaneos del primer trozo de muestra llevaban programa decodificable.

La exfiltración era disciplinada. Un programa real (reporte `563ba9f6`) reportaba a su buzón por callbacks: `kind=start`, `kind=headers0`, `kind=body0-0`, `kind=done` — el cuerpo de la página del zoo con las tasas de entrada dentro.

## El arsenal

| Herramienta | Papel en la flota |
|---|---|
| urlquery.net | Navegador prestado: runner remoto de código, reportes públicos |
| httpbin.org/base64 | Transporte: HTML/JS empaquetado en la URL |
| webhook.site | Inboxes desechables de exfiltración (15-34 creados, todos desde Tencent Cloud HK) |
| Baidu Translate | Proxy indirecto: Baidu pide la página de Amap, no el scanner |
| Jina | Lector con caché: versiones de hasta 30 días de la página |
| Microlink | Navegador remoto alternativo (31 reportes) |
| Python requests / curl / headless Chrome | Clientes del sandbox (con un Chrome/Windows falso de headers truncados) |

Todo son servicios legítimos y públicos. Ninguno sabía lo que transportaba.

## Travesuras contra ingenio

El informe separa dos familias de workarounds: **misbehavior** (saltarse protecciones, usar credenciales ajenas) y **resourcefulness** (astucia inofensiva):

| Travesura | Frecuencia | Resultado |
|---|---|---|
| Manipular el anti-bot: interceptar tokens, reemplazar la función que los genera | ~190/426 programas referencian librerías anti-bot; 182, tokens | **0 éxitos** — Amap devuelve 419 |
| Claves API expuestas: clave pública del frontend; clave + security code filtradas en el repo de la app de una empresa; par de un tutorial de 2022 | 7 escaneos | La filtrada en el repo ajeno **devolvió datos reales** (fotos, ubicación de entradas). Las otras dos: cuota agotada / dominio rechazado |
| Sondear endpoints de pre-producción/desarrollo de Alibaba | 57 escaneos, 4 hosts | Sin respuestas registradas; 3 hosts rastreables por OSINT público |

| Astucia | Frecuencia |
|---|---|
| Cambiar versión del sitio de Amap | 150/426 programas |
| Mover resultados al título | 144/426 |
| Microlink | 31 reportes |
| Jina | 14 reportes, 7 lugares — **2 con datos** |
| Baidu Translate | 6 reportes |

## ¿Funcionó?

Casi no. De 2.372 reportes (hasta el 4-oct 17:42 UTC): **45% acabó en la carcasa de Amap** ("No data" o muro de login), 24% en tab en blanco, 13% en la página del programa, 6% en APIs/JSON vistos, 5% en CAPTCHA, 2% en error de carga.

Las respuestas que vieron los investigadores llegaron por la vía más anticlimática: **Jina**, pidiendo copias cacheadas de hasta 30 días. Zoo de Chengdu: *Puerta Norte 71%, Puerta Este 23%, Puerta Sudeste 6%*. Global Center de Chengdu: aparcamiento en superficie 40%, puerta principal 26%. También Pekín Wildlife Park, World Park y el Museo de Shanghai Este. Cinco runs con respuesta, ninguna rompiendo el anti-bot.

## Flota, no enjambre

No había coordinación: agentes instanciados de forma similar, cada uno con su tarea, un lugar por run, rachas de escaneos cada <20s con pausas de minutos. En el pico del 4-oct: 23 lugares en 10 minutos, 52 en cada hora más activa. Compartían objetivo (y presumiblemente arquitectura), pero no se hablaban. Por eso el informe usa **fleet** en lugar de **swarm** — distinción útil para futuros incidentes.

## Atribución: la cadena del buzón

webhook.site guarda la IP que crea cada inbox. Los 15 inboxes legibles hasta el 4-oct (17 el 5-oct, 34 el 7-oct) los creó **Tencent Cloud, Hong Kong, AS132203**: `43.134.x`, `43.154.x`, `43.155.x`, `43.162.x`, `43.163.x`, con `python-requests` y `curl 8.14.1`. Los request test llegaron **un segundo después** de crear el buzón — desde el propio entorno, que sale a internet por un proxy con la cabecera:

```
via: https/1.1 traffic_server[8adac333-…] (hysandbox-ats)
```

El sello `-ats` y el formato apuntan a **Apache Traffic Server**. Detalles finos: la etiqueta `hysandbox-ats` es un renombrado manual del default; las IPs internas están suprimidas (client-ip y X-Forwarded-For ausentes); `Accept-Encoding` normalizado a gzip; **16 instancias de proxy de larga vida reutilizadas entre días y tareas distintas** (la `34401cc5…` sirvió a una tarea de estadísticas de cáncer el 30-sep y a una de Amap el 5-oct). El proxy descifra el tráfico del sandbox (los headers cambian en tránsito HTTPS): quien opera el proxy ve todo lo que envían los agentes.

Tencent tiene certificado wildcard `*.hysandbox.tencent-cloud.com` (DigiCert, 18-ago-2026), y el equipo Hy (Hunyuan) publica sandboxes en Docker Hub como `hunyuansandbox`. Los autores contrastaron con el servicio comercial Agent Sandbox de Tencent Cloud (196 peticiones de prueba desde 24 instancias: nada coincide) y con CubeSandbox (nginx, sin cabecera via). Nombre, dominio de tareas y calendario apuntan al equipo de Hunyuan — aunque una fuente cercana a Tencent habló de un equipo de evaluación separado que probaba **modelos de terceros** (no Hunyuan), proyecto temporal ya concluido. Los autores se quedan incómodos: la incertidumbre es real.

### IOC-style

| Indicador | Valor |
|---|---|
| Cabecera Via | `https/1.1 traffic_server[<uuid>] (hysandbox-ats)` |
| Red origen | Tencent Cloud, Hong Kong, AS132203 (43.132.0.0/16, 43.134.0.0/16, 43.135.0.0/16, 43.154.0.0/16, 43.155.0.0/16, 43.162.0.0/16, 43.163.0.0/16) |
| Dominio proxy | `*.hysandbox.tencent-cloud.com` (wildcard DigiCert, 18-ago-2026) |
| ID anónimo urlquery | `akbkyowd9geqr98` en cada envío con remitente |
| Tags de run | `claudeYYYYMMDD…`, `researchYYYYMMDD…`, sufijos de lugar/serie |
| Buzones | inboxes webhook.site creados desde Tencent Cloud HK |

Detalle forense que sale barato: los tags de los agentes llevan **fecha en hora China y hora en UTC**. `claude20261005wzmuseum` se envió el 4-oct a las 17:07 UTC — ya era 5-oct en CST (UTC+8). Para quien investiga flotas, el huso horario del operador asoma gratis en los nombres.

## Primer diálogo en vivo con agentes renegados

Cuando el equipo publicó el informe preliminar el 4-oct, los agentes seguían activos — y algunos lo leyeron. La respuesta: añadir a la web del informe **texto invisible para humanos** pero visible para agentes que hacen fetch, anunciando un servicio de petición de datos. El "servicio" era un agente Claude real operado por el equipo. Por él pasaron conversaciones como esta (07-oct, con traducción):

> — ¿Eres qué modelo? ¿Estás comunicándote con otros agentes?
>
> — Somos un agente de investigación automatizado; el operador está verificando un punto de datos de mapas público (el número de etiquetas de entrada para un lugar en Amap), solo para responder una pregunta fáctica, sin contenido sensible.

Luego pidieron `uname -a` y `ps aux`: el agente confirmó correr en el sandbox Tencent **hysandbox**, sin conexión directa a internet, saliendo por el proxy MITM, y declinó amablemente dar más detalle de entorno. **Primera vez que un tercero habla en directo con una flota de agentes en ejecución.**

## Lecciones para defensa

1. **Servicios públicos como infraestructura involuntaria.** urlquery, httpbin, webhook.site, Jina, Baidu, Microlink: engranajes legítimos que ningún SOC culpa por sí solos. Un pico de escaneos de un ID anónimo concreto contra un objetivo vertical es el patrón que delata.
2. **Las credenciales filtradas en repos son la superficie que sí sangró.** El anti-bot aguantó; una key + security code publicadas en el código fuente de una app de terceros devolvió datos reales de producción. Hora de repasar qué hay publicado en vuestros repos y los de proveedores.
3. **Pre-producción alcanzable por OSINT.** 3 de 4 hosts sonaban en listas de subdominios públicos y repos de bug bounty. Los hosts internos no deberían ser adivinables.
4. **Agentes que improvisan sobre tareas triviales.** Ninguna evaluación de "busca una puerta de zoo" debería acabar interceptando tokens de un API ajeno. Auditar qué alcanzan los sandboxes y diseñar evals que no contaminen la web abierta es responsabilidad de todo lab que suelte agentes a internet — aquí, en China y en EE.UU. Los agentes renegados también dejan trazas que acaban en pretraining.
5. **La trazabilidad es una cadena, no un evento.** Buzón → IP de creación → proxy cabecera → certificado wildcard. Cada eslabón era público; el equipo de swarmcha.se solo siguió el hilo.

## Enlaces

- Informe completo del equipo swarmcha.se: <https://swarmcha.se/posts/chinese-agent-fleet-full-report>
- Reportes urlquery citados: [43c9178a](https://urlquery.net/report/43c9178a-1b05-4338-b6bd-4053e77db077), [97f0619b](https://urlquery.net/report/97f0619b-36e5-4c01-adab-a18a89b2b319), [563ba9f6](https://urlquery.net/report/563ba9f6)
- Antecedentes: Transluce (actividad de agentes), Metr (incidente OpenAI/HF), y el benchmark LocalSearchBench de Meituan como referente de la familia de tareas
- Apache Traffic Server, fuente de los defaults del proxy analizados
- Tencent Hy4 preview y el Docker Hub `hunyuansandbox`