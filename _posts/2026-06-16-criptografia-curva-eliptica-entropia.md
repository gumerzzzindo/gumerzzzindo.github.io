---
layout: single
title: "Criptografía de Curva Elíptica y Entropía: los fundamentos que sostienen todo"
date: 2026-06-16
categories: [tutoriales]
tags: [criptografia, ecc, curva-eliptica, entropia, rng, ecdsa, ecdh, post-cuantica]
excerpt: "Cómo funciona la criptografía de curva elíptica (ECC), por qué la entropía del generador de números aleatorios es el eslabón más débil, y qué pasa cuando falla."
permalink: /tutoriales/criptografia-curva-eliptica-entropia/
---

ECDSA, ECDH, Ed25519, Curve25519. Si has tocado SSH, TLS, Signal o un wallet de Bitcoin, has usado curva elíptica sin pensarlo. Y casi siempre el problema no está en la matemática, sino en la entropía que alimenta esa matemática. Vamos a desmontar ambas piezas.

---

## RSA vs Curva Elíptica: por qué ganó ECC

RSA basa su seguridad en la dificultad de factorizar números grandes. ECC basa la suya en el **problema del logaritmo discreto en curvas elípticas** (ECDLP). La diferencia práctica es brutal:

| Seguridad equivalente | RSA (bits de clave) | ECC (bits de clave) |
|---|---|---|
| 80 bits | 1024 | 160 |
| 128 bits | 3072 | 256 |
| 192 bits | 7680 | 384 |
| 256 bits | 15360 | 512 |

Con ECC consigues el mismo nivel de seguridad con claves muchísimo más pequeñas, lo que significa firmas más rápidas, menos tráfico de red y mejor rendimiento en dispositivos con poca CPU (IoT, smartcards, TLS a escala).

---

## La curva, en corto

Una curva elíptica sobre un cuerpo finito se define como:

```
y² = x³ + ax + b (mod p)
```

Los puntos que satisfacen esta ecuación, junto con un punto en el infinito, forman un grupo. Se define una operación de "suma de puntos" con propiedades geométricas (la recta que une dos puntos de la curva corta en un tercer punto, que se refleja). A partir de ahí:

- **Multiplicación escalar**: `Q = k·P`, sumar el punto `P` consigo mismo `k` veces.
- **Problema difícil**: dado `Q` y `P`, encontrar `k` es computacionalmente inviable si la curva está bien elegida.

`k` es la clave privada. `Q` es la clave pública. Toda la seguridad de ECDSA y ECDH descansa en que invertir esa multiplicación es intratable.

### Curvas más usadas

- **secp256k1** — Bitcoin, Ethereum. Parámetros "verificablemente aleatorios" según sus autores, aunque ha habido debate sobre el origen de las constantes.
- **P-256 (secp256r1)** — NIST, omnipresente en TLS. Generada por la NSA con una semilla que nunca se explicó públicamente, lo que generó desconfianza tras las filtraciones de Snowden.
- **Curve25519 / Ed25519** — diseñada por Daniel J. Bernstein, parámetros derivados de forma transparente y determinista. Es la curva de referencia en SSH, Signal, WireGuard.

La elección de curva no es solo rendimiento: es también una decisión de confianza sobre quién generó los parámetros y cómo.

---

## Firmar y verificar con ECDSA

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()

mensaje = b"transaccion firmada"
firma = private_key.sign(mensaje, ec.ECDSA(hashes.SHA256()))

public_key.verify(firma, mensaje, ec.ECDSA(hashes.SHA256()))
```

ECDSA necesita un valor aleatorio (`k`, el nonce) en cada firma. Y aquí es donde la teoría limpia choca con la realidad: **si ese nonce se reutiliza o tiene baja entropía, la clave privada se puede recuperar matemáticamente.**

---

## El verdadero punto débil: la entropía

Toda la seguridad de ECC depende de que el generador de números aleatorios (RNG) produzca valores impredecibles. Si la fuente de entropía está comprometida, la curva más elegante del mundo no sirve de nada.

### Caso real: PS3 y el nonce reutilizado

Sony reutilizó el mismo valor de `k` en todas las firmas ECDSA de la PS3 en lugar de generarlo aleatoriamente. Con dos firmas distintas usando el mismo `k`, despejar la clave privada es álgebra de instituto:

```
s1 = k⁻¹(h1 + r·d) mod n
s2 = k⁻¹(h2 + r·d) mod n
```

Restando ambas ecuaciones, `k` se cancela parcialmente y `d` (la clave privada) queda despejable. El grupo fail0verflow extrajo la clave raíz de firmware de la PS3 explotando exactamente esto en 2010.

### Caso real: Debian OpenSSL (2006-2008)

Un parche en Debian eliminó por error la inicialización de entropía en OpenSSL, reduciendo el espacio de claves generables a apenas 32.768 posibilidades por arquitectura. Cualquier clave SSH o certificado generado en ese periodo era trivialmente fuerza-bruteable. Tardó **dos años** en detectarse.

### Entropía en sistemas embebidos y IoT

Los dispositivos sin disco, sin interacción de usuario y que arrancan siempre desde el mismo estado tienen un problema estructural: poca fuente de ruido real para alimentar `/dev/random`. Estudios sobre claves RSA/ECC en routers domésticos han encontrado miles de dispositivos compartiendo la misma clave privada porque generaron sus claves segundos después de un boot idéntico, con el mismo pool de entropía.

---

## Cómo se mide y se genera entropía decente

```bash
# Comprobar entropía disponible en el pool del kernel Linux
cat /proc/sys/kernel/random/entropy_avail

# Generar bytes aleatorios criptográficamente seguros
openssl rand -hex 32

# Auditar la calidad estadística de una fuente de entropía
rngtest < /dev/random
```

Fuentes de entropía real en hardware moderno:

- **RDRAND/RDSEED** (Intel/AMD) — generador hardware integrado en la CPU. Útil pero no debe ser la *única* fuente (hubo dudas sobre posible debilitamiento por requisitos de exportación en el pasado).
- **Ruido de interrupciones del kernel** — timing de I/O, red, teclado/ratón.
- **TRNG dedicados (QRNG)** — generadores cuánticos de números aleatorios, que extraen entropía de fenómenos físicos genuinamente probabilísticos en lugar de pseudoaleatoriedad determinista.

La recomendación práctica: nunca confíes en una sola fuente. Los sistemas serios (el `/dev/urandom` moderno de Linux, por ejemplo) mezclan múltiples fuentes con un CSPRNG antes de entregar bytes.

---

## ¿Y la computación cuántica?

El algoritmo de Shor rompe tanto RSA como ECC en tiempo polinómico con un ordenador cuántico suficientemente grande. La diferencia: ECC con claves de 256 bits cae más rápido frente a Shor que RSA de 3072 bits, precisamente porque sus claves son más pequeñas para el mismo nivel de seguridad clásica.

Esto es lo que motiva la migración a criptografía post-cuántica (CRYSTALS-Kyber para intercambio de claves, CRYSTALS-Dilithium para firmas, ya estandarizados por NIST). Mientras tanto, el riesgo de **harvest now, decrypt later** es real: tráfico cifrado con ECDH hoy puede estar siendo capturado para descifrarse en cuanto exista capacidad cuántica suficiente.

---

## Resumen práctico

- ECC no es per se "mejor" que RSA, es más eficiente para el mismo nivel de seguridad.
- La curva que eliges importa: prefiere Curve25519/Ed25519 sobre curvas NIST si puedes elegir y no tienes requisitos de compliance que lo impidan.
- El fallo casi nunca está en las matemáticas de la curva. Está en el RNG que genera el nonce o la clave.
- Auditar la entropía del sistema (`entropy_avail`, fuentes mezcladas, RNG hardware) es tan importante como elegir bien el algoritmo.
- La migración a post-cuántica no es ciencia ficción, es una cuenta atrás con fecha desconocida pero certeza de llegada.
