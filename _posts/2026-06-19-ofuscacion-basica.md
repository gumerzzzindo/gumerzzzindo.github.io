---
layout: single
title: "Ofuscación básica: XOR, stack strings, control flow flattening y crackmes.de"
date: 2026-06-19
categories: [reversing, tutoriales]
tags: [ofuscacion, xor, stack-strings, control-flow, crackmes, reversing]
excerpt: "Técnicas de ofuscación que verás en el 90% de los binarios protegidos: XOR encoding, cadenas en pila, aplanamiento de flujo y dónde practicar."
permalink: /reversing/ofuscacion-basica/
---

Esta es la entrega 6 de la serie [Reversing para principiantes](/reversing/).

En la entrega anterior vimos [calling conventions](/reversing/calling-conventions/) y cómo identificarlas en ensamblador. Ahora damos un paso más: los autores de malware y protecciones comerciales no quieren que leas su código con facilidad. Usan ofuscación. Este post cubre las técnicas más comunes que encontrarás en la práctica.

---

## Por qué existe la ofuscación

El objetivo no es hacer el binario imposible de analizar —eso es imposible— sino aumentar el tiempo y esfuerzo necesarios. Las técnicas básicas atacan tres vectores:

- **Strings visibles**: `strings binary` o Ghidra revelan inmediatamente URLs, mensajes de error, claves.
- **Flujo de control legible**: si el CFG (Control Flow Graph) es limpio, seguir la lógica es trivial.
- **Datos estáticos**: constantes, tablas, buffers que identifican el propósito del código.

---

## XOR encoding

La técnica más antigua y más usada. Toma un buffer de datos y aplica XOR con una clave de un byte (o más).

```c
void xor_decode(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= key;
}
```

En ensamblador x86-64 esto aparece como un bucle con `xor byte ptr [rax], cl` o similar. Lo reconocerás porque:

1. Hay una operación XOR dentro de un bucle que itera sobre un buffer.
2. El resultado se usa poco después (llamada a función, salto condicional basado en la comparación).
3. La clave suele ser una constante inmediata: `xor byte ptr [rax+rcx], 0x42`.

### Cómo resolverlo estáticamente

En Ghidra, identifica el bucle XOR y busca el buffer de entrada y la clave. Luego usa el script de Python integrado:

```python
key = 0x42
data = bytes([0x26, 0x2F, 0x27, 0x2B, 0x30, 0x27, 0x07])
print(bytes([b ^ key for b in data]))
```

Si la clave es de múltiples bytes (rolling XOR), el patrón es `key[i % key_len]`:

```python
key = b"\x13\x37\xDE\xAD"
data = bytearray(...)
result = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
```

### Identificación rápida

Cuando ves un bloque de bytes que no parece ASCII ni código válido, intenta XOR con bytes comunes (0x00 revela el XOR key, 0xFF invierte bits, 0x20 alterna mayúsculas/minúsculas). La herramienta `xortool` automatiza esto buscando la clave más probable por frecuencia de caracteres.

---

## Stack strings

Los strings normales van en la sección `.rodata` (Linux) o `.rdata` (Windows) y aparecen directamente en `strings`. Las stack strings los construyen carácter a carácter en la pila en tiempo de ejecución:

```c
char cmd[8];
cmd[0] = 'c';
cmd[1] = 'm';
cmd[2] = 'd';
cmd[3] = '.';
cmd[4] = 'e';
cmd[5] = 'x';
cmd[6] = 'e';
cmd[7] = '\0';
WinExec(cmd, SW_HIDE);
```

El compilador genera algo como:

```nasm
mov byte [rbp-8], 0x63   ; 'c'
mov byte [rbp-7], 0x6D   ; 'm'
mov byte [rbp-6], 0x64   ; 'd'
mov byte [rbp-5], 0x2E   ; '.'
mov byte [rbp-4], 0x65   ; 'e'
mov byte [rbp-3], 0x78   ; 'x'
mov byte [rbp-2], 0x65   ; 'e'
mov byte [rbp-1], 0x00
```

Los compiladores optimizados lo condensan usando mov dword o mov qword con el valor empaquetado:

```nasm
mov dword [rbp-8], 0x2E646D63   ; "cmd." en little-endian
mov dword [rbp-4], 0x00657865   ; "exe\0"
```

### Detección en Ghidra

Ghidra no reconoce estas como strings automáticamente. Busca secuencias de `MOV BYTE` o `MOV DWORD` consecutivos apuntando a offsets contiguos de la misma variable local. El plugin **FLOSS** (FireEye Labs Obfuscated String Solver) automatiza la detección ejecutando el código en un emulador y capturando los strings resultantes:

```bash
floss malware.exe
```

---

## Control flow flattening

Esta técnica destruye la estructura natural del CFG. El código original:

```c
if (check_license()) {
    feature_a();
} else {
    show_nag();
}
feature_b();
```

Se transforma en una máquina de estados con un dispatcher central:

```c
int state = initial_state;
while (1) {
    switch (state) {
        case 0xA1B2: state = check_license() ? 0xC3D4 : 0xE5F6; break;
        case 0xC3D4: feature_a(); state = 0x1122; break;
        case 0xE5F6: show_nag(); state = 0x1122; break;
        case 0x1122: feature_b(); return;
    }
}
```

En Ghidra, el CFG se ve como muchos bloques básicos pequeños que todos convergen en un bloque central (el dispatcher) y salen hacia bloques individuales. El patrón distintivo: una variable que actúa como "selector de estado" que se actualiza al final de cada bloque y se lee al principio del dispatcher.

### Estrategia de análisis

1. **Identifica el dispatcher**: el bloque que se repite más en el CFG, normalmente con un switch o serie de comparaciones contra constantes.
2. **Rastrea la variable de estado**: su valor inicial determina el punto de entrada real.
3. **Construye el CFG real**: sigue manualmente qué estado lleva a qué. Una tabla ayuda:

| Estado actual | Condición | Estado siguiente |
|--------------|-----------|-----------------|
| 0xA1B2 | resultado != 0 | 0xC3D4 |
| 0xA1B2 | resultado == 0 | 0xE5F6 |
| 0xC3D4 | — | 0x1122 |

4. **Herramientas**: [miasm](https://github.com/cea-sec/miasm) y [angr](https://angr.io/) pueden recuperar el CFG real automáticamente mediante ejecución simbólica.

---

## Comparativa de técnicas

| Técnica | Dificultad de implementar | Dificultad de analizar | Impacto en rendimiento |
|---------|--------------------------|------------------------|------------------------|
| XOR single-byte | Muy baja | Muy baja | Mínimo |
| XOR multi-byte | Baja | Baja | Mínimo |
| Stack strings | Baja | Media | Bajo |
| Control flow flattening | Media | Alta | Medio-alto |
| Combinación de las tres | Media | Alta | Medio |

---

## Práctica en crackmes.de

[crackmes.de](https://crackmes.one) es el repositorio más grande de crackmes clasificados por dificultad (1-6) y plataforma. Para practicar las técnicas de este post:

**Búsqueda recomendada**: dificultad 2-3, plataforma Linux o Windows, lenguaje C/C++.

Proceso estándar:

```bash
# Descarga y descomprime (contraseña habitual: crackmes.one)
unzip crackme.zip -d crackme/ -P crackmes.one

# Reconocimiento inicial
file crackme/crackme
strings crackme/crackme | grep -E '[A-Za-z]{4,}'
checksec --file=crackme/crackme
```

```bash
# Si hay strings sospechosamente ausentes → probable ofuscación
# Ejecuta con argumento cualquiera para ver el comportamiento
./crackme test123
```

Una vez en Ghidra:

1. Busca la función `main` o el punto de entrada.
2. Localiza la comparación que determina "correcto" vs "incorrecto".
3. Sigue hacia atrás desde esa comparación para entender cómo se procesa la entrada.
4. Si hay XOR, extrae los parámetros y decodifica offline.
5. Si hay stack strings, reconstruye manualmente o usa FLOSS.

---

## Señales de alerta en un binario

Cuando abras un binario nuevo, estos indicadores sugieren ofuscación:

- `strings` devuelve muy pocos strings legibles para el tamaño del binario.
- Hay secciones con entropía alta (>7.0 bits/byte). Compruébalo con `binwalk -E binary` o `entropy` en Ghidra (right-click en sección → Properties).
- La sección `.text` tiene entropía alta pero el binario no usa un packer conocido.
- Hay un bucle temprano en `main` antes de cualquier lógica real (probable decoder).

---

## Siguiente paso

En la próxima entrega veremos cómo compilar el mismo código C con `-O0` y `-O2` y qué cambios produce el optimizador en el ensamblador resultante —una habilidad clave para reconocer patrones de código de alto nivel en binarios compilados.

Los crackmes de dificultad 2-3 en crackmes.one con las técnicas de este post son la práctica ideal antes de seguir.
