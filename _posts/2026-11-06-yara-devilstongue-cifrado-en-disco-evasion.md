---
title: "YARA no lee ensamblador: anatomía de una regla de DevilsTongue y por qué el malware se cifra en disco"
date: 2026-11-06
layout: single
author_profile: true
read_time: true
toc: true
toc_label: "Índice"
toc_sticky: true
categories:
  - malware-analysis
tags:
  - yara
  - malpedia
  - devilstongue
  - evasion
  - memory-forensics
  - soc
excerpt: "Qué hay realmente dentro de una regla YARA autogenerada, por qué las firmas en disco fallan contra malware cifrado y qué mira un SOC cuando la evasión gana la carrera."
---

Hace unos días, revisando la ficha de **DevilsTongue** en Malpedia, me surgió una duda aparentemente tonta: *¿las reglas YARA buscan código ensamblador?* La respuesta corta es no. La larga da para un post, porque al contestarla se entiende también por qué buena parte del malware avanzado llega cifrado a disco y qué significa eso para quien monitoriza desde un SOC.

## 1. Contexto: DevilsTongue

DevilsTongue es un malware modular y multihilo, escrito en C y C++, atribuido al actor **Caramel Tsunami** (SOURGUM / Candiru) y descrito por Microsoft en julio de 2021 en su análisis sobre un actor privado que vendía 0-days y malware a terceros.

Según esa descripción, los puntos que más nos interesan aquí son:

- En disco se eliminan las rutas PDB y los timestamps del PE.
- Cadenas y configuración van cifradas.
- Cada fichero tiene un hash único.
- La funcionalidad principal vive en **DLLs cifradas en disco** que solo se descifran en memoria.
- La configuración y el *tasking* están separados del binario.
- Tiene capacidades en modo usuario y en modo kernel.

Es decir: está diseñado para que casi nada de lo que se puede escanear en disco sea útil.

## 2. ¿Qué busca realmente una regla YARA?

YARA compara **patrones de bytes**, no instrucciones. Un analista puede *pensar* en ensamblador al escribir una regla, pero el motor solo ve bytes. Además de secuencias hexadecimales admite:

- Cadenas de texto (ASCII y wide) y expresiones regulares.
- Condiciones sobre tamaño y offsets.
- El módulo `pe` (imports, secciones, timestamps, rich header...).
- Los módulos `hash` y `math` (por ejemplo, entropía).

### La regla de Malpedia para DevilsTongue

La regla `win_devilstongue_auto` está generada automáticamente por **yara-signator** (autor: Felix Bilstein, licencia CC BY-SA 4.0). Fíjate en una de sus secuencias:

```
$sequence_1 = { 4883ec28 4889d1 e8???????? b801000000 4883c428 c3 56 }
```

Decodificada a mano, son instrucciones x64 normales:

| Bytes | Instrucción |
|-------|-------------|
| `4883ec28` | `sub rsp, 0x28` |
| `4889d1` | `mov rcx, rdx` |
| `e8????????` | `call <wildcard>` |
| `b801000000` | `mov eax, 1` |
| `4883c428` | `add rsp, 0x28` |
| `c3` | `ret` |
| `56` | `push rsi` |

Observaciones útiles:

- Los `????????` son **comodines** sobre el desplazamiento del `call`. Así la regla sobrevive a una recompilación donde cambian las direcciones relativas.
- La configuración `callsandjumps;datarefs;binvalue` indica que se enmascaran llamadas, saltos y referencias a datos, y que se conservan los valores constantes.
- Algunas secuencias contienen comparaciones con constantes de 32 bits seguidas de saltos condicionales, por ejemplo `81fa15b7785c 75f0 ... ba251f32f5`. Es un patrón compatible con un *dispatcher* de flujo de control aplanado (una variable de estado comparada contra constantes), aunque esto es una interpretación mía y habría que confirmarlo en un desensamblador.
- La condición final es `7 of them and filesize < 990208`: al menos 7 de 10 secuencias en un fichero de menos de ~967 KB.

> **Ojo con los comentarios de la regla.** Los comentarios de desensamblado que acompañan a cada secuencia en Malpedia no coinciden con los bytes (aparecen instrucciones de 32 bits mezcladas con prefijos x64). Para entender la regla, decodifica los bytes tú mismo.
{: .notice--warning}

### Limitaciones que hay que tener presentes

Malpedia lo avisa en el propio disclaimer: las cadenas se seleccionan automáticamente desde **volcados de memoria y ficheros desempaquetados**, y para muchas familias solo hay una muestra documentada. Traducción práctica: la regla generaliza poco y **no va a saltar contra el fichero cifrado en disco**. Hay que aplicarla sobre memoria o sobre el payload ya descifrado.

## 3. ¿Por qué cifrar en disco y descifrar en memoria?

Porque desplaza el problema de la detección:

1. **Anula la firma estática.** Sin cadenas ni opcodes legibles, YARA y los motores AV de disco ven ruido.
2. **Hash único por muestra.** Una clave distinta por compilación cambia todos los bytes; el hash no sirve como IOC.
3. **El payload real solo existe en RAM**, tras ejecutar un *loader* pequeño y barato de rehacer.
4. **Separar configuración y *tasking*.** Con una muestra sola no obtienes C2 ni objetivos.
5. **Ejecución condicionada (*keying*).** Si la clave se deriva del entorno de la víctima, un sandbox no descifra nada útil.

### ¿Es metamorfismo?

No exactamente. Conviene separar:

- **Polimorfismo / empaquetado**: el mismo código dentro de una envoltura cifrada distinta cada vez. Es lo descrito arriba.
- **Metamorfismo**: el propio código se reescribe (reordenación, sustitución de instrucciones, código basura). Es más caro y menos habitual; hoy se parece más a la ofuscación mediante compiladores o máquinas virtuales (tipo VMProtect o Themida).

## 4. Panorama actual de técnicas de evasión

Visión general, a nivel conceptual:

**Contra el análisis estático**
- Packers y *crypters*, cifrado de cadenas, resolución dinámica de APIs por hash.
- Aplanado de flujo de control, predicados opacos, código basura.
- Limpieza de metadatos (PDB, timestamps, *rich header*).

**Contra el EDR en ejecución**
- Evitar los *hooks* de userland: syscalls directas o indirectas, *unhooking* de `ntdll`.
- Neutralizar telemetría como AMSI o ETW.
- Ejecución exclusivamente en memoria: carga reflectiva y módulos mapeados a mano.
- Inyección de procesos y variantes (*hollowing*, *module stomping*...).
- Ofuscar el implante mientras duerme (*sleep masking*) para escapar de escaneos de memoria periódicos.
- Falsificación de la pila de llamadas (*call stack spoofing*).

**Contra las defensas del sistema**
- *BYOVD*: cargar un driver legítimo pero vulnerable para cegar al EDR desde kernel.
- Capacidades en modo kernel para manipular callbacks de notificación.
- Abuso de binarios firmados: LOLBins y *DLL sideloading*.

**Contra la red y el análisis dinámico**
- C2 detrás de CDN, redirectores o servicios legítimos en la nube.
- Detección de sandbox y de máquinas virtuales, comprobaciones de tiempo e interacción del usuario.

## 5. Qué puede hacer la defensa

Si la firma en disco pierde peso, la detección se desplaza hacia otros sitios:

- **Memoria**: regiones `RWX` o cambios `RW → RX` recientes, código ejecutable sin fichero asociado, PEs en memoria sin módulo legítimo (Volatility `malfind`, escaneos YARA de procesos).
- **Telemetría de kernel**: ETW Threat Intelligence, eventos de carga de drivers, cambios en callbacks.
- **Comportamiento**: procesos padre anómalos, `ntdll` en memoria distinto del de disco, syscalls originadas fuera de `ntdll`.
- **Drivers**: listas de drivers vulnerables conocidos (LOLDrivers), bloqueo de Microsoft, HVCI.
- **Red**: *beaconing* regular, huellas JA3/JA4, dominios recién registrados.
- **Entropía alta** en secciones: indicio, nunca prueba.

En la práctica, con una herramienta como **Velociraptor** puedes lanzar la regla contra procesos en lugar de contra el disco (por ejemplo con el artefacto `Windows.Detection.Yara.Process`) y combinar el resultado con los IOCs publicados del actor.

## 6. Conclusiones

- YARA compara bytes; el ensamblador es una ayuda para quien escribe y lee las reglas.
- Una regla autogenerada es una **pista de baja confianza**, no un veredicto.
- Cifrar en disco y descifrar en RAM es barato para el atacante y caro para el defensor; por eso la detección útil sube hacia memoria, kernel y comportamiento.
- Si analizas una familia así, trabaja con volcados o con el payload desempaquetado.

## Referencias

- Malpedia, ficha de [win.devilstongue](https://malpedia.caad.fkie.fraunhofer.de/details/win.devilstongue) (regla `win_devilstongue_auto`, Felix Bilstein, CC BY-SA 4.0).
- Microsoft Threat Intelligence, *Protecting customers from a private-sector offensive actor using 0-day exploits and DevilsTongue malware* (15/07/2021).
- [yara-signator](https://github.com/fxb-cocacoding/yara-signator).
