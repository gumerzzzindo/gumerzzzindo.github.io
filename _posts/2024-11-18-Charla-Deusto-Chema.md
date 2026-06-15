---
layout: single
title: "Charla de Chema Alonso en Deusto: IA, Cuántica y Ciberseguridad"
date: 2024-11-18
categories: [blog]
tags: [ia-generativa, ciberseguridad, quantum, chema-alonso, charla, gan, deepfake]
excerpt: "Apuntes de la charla de Chema Alonso en la Universidad de Deusto sobre el impacto de la IA generativa, la computación cuántica y los retos de seguridad que vienen."
permalink: /blog/charla-deusto-chema-alonso/
---

El 18 de noviembre de 2024 asistí a una charla de Chema Alonso en la Universidad de Deusto (Bilbao). El tema: cómo la IA generativa y la computación cuántica están redefiniendo la ciberseguridad. Estos son mis apuntes.

---

## IA Generativa

La parte más densa de la charla. Chema arrancó con los fundamentos matemáticos detrás de los modelos generativos: **interpolación en espacios latentes**, que es básicamente cómo los modelos "inventan" contenido nuevo a partir de puntos conocidos en un espacio multidimensional.

Repasó las arquitecturas principales:

- **CNN (Redes Neuronales Convolucionales)**: procesamiento de imágenes, upscaling, mejora de calidad
- **RNN (Redes Neuronales Recurrentes)**: generación de secuencias — texto, música, código
- **GANs (Redes Generativas Antagónicas)**: el generador crea contenido falso, el discriminador aprende a detectarlo. En el entrenamiento compiten hasta que el generador engaña al discriminador consistentemente

En la parte práctica mencionó herramientas como **DeepCamLive** para generación de vídeo en tiempo real y técnicas de reconstrucción facial. El foco era claro: los deepfakes ya no son un problema futuro.

Lo que me quedé: la brecha entre "detectar deepfakes" y "generarlos" se está cerrando muy rápido. Los discriminadores de hoy son los modelos de mañana.

---

## Computación Cuántica y Criptografía

Aquí el tono cambió. Menos demos, más amenaza real. El concepto central fue **QuantumReadiness**: preparar los sistemas actuales antes de que los ordenadores cuánticos rompan RSA y curvas elípticas.

Los puntos clave:

- **Harvest now, decrypt later**: actores de amenaza ya están capturando tráfico cifrado hoy para descifrarlo cuando tengan capacidad cuántica suficiente. No es hipotético, está pasando.
- **Algoritmos post-cuánticos**: el NIST ya ha estandarizado los primeros (CRYSTALS-Kyber, CRYSTALS-Dilithium). Las organizaciones críticas deberían estar migrando.
- **Generadores de números aleatorios cuánticos (QRNG)**: hardware que usa fenómenos cuánticos para generar entropía real, sin predictibilidad matemática. Relevante para criptografía de alta seguridad.

El mensaje era directo: la criptografía simétrica fuerte (AES-256) sobrevive al cuántico relativamente bien. La asimétrica (RSA, ECDH) no.

---

## Ciberseguridad en el Contexto Actual

La última parte fue más conceptual. Algunos puntos que me parecieron interesantes:

**Autenticación:**
- **OTP (One-Time Passwords)**: útiles, pero vulnerables a phishing en tiempo real (evilginx, modlishka). La 2FA no es bala de plata.
- **OAuth y gestión de identidad**: el vector de ataque se ha desplazado de las contraseñas a los tokens. Robar el refresh token es más rentable que crackear la password.

**Detección:**
- Defendió los sistemas **IDS/IPS con correlación activa** frente a firewalls estáticos. La sonda que monitoriza comportamiento anómalo es más útil que la regla que bloquea puertos conocidos.

**Reflexión final de la charla:**
> "La superficie de ataque crece más rápido que nuestra capacidad de defenderla. La IA ofensiva ya está en manos de actores malos. La pregunta no es si usarán IA para atacar, sino cuándo dejaremos de pretender que no."

---

Buena charla. Densa en algunos momentos, pero el hilo conductor entre IA generativa → deepfakes → confianza digital → cuántica → criptografía futura tiene mucho sentido visto así. Lo del harvest now, decrypt later me pareció lo más relevante para pensar en el corto plazo.
