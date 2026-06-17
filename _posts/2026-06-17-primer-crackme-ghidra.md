---
layout: single
title: "Tu primer crackme con Ghidra: instalación, navegación y parchear un strcmp"
date: 2026-06-17
categories: [reversing, tutoriales]
tags: [ghidra, crackme, reversing, patching, strcmp, decompilador, análisis-estático]
excerpt: "Instala Ghidra, carga tu primer binario, navega el decompilador y parchea un strcmp para que la verificación de contraseña siempre pase."
permalink: /reversing/primer-crackme-ghidra/
---

Esta es la entrega 3 de la serie [Reversing para principiantes](/reversing/).

Si no has leído el post anterior sobre [anatomía de binarios ELF/PE](/reversing/anatomia-binario-elf-pe/), hazlo primero: aquí se asume que sabes qué es `.text`, qué hace la IAT y por qué el entry point no es `main`.

---

Ghidra es el descompilador de referencia para análisis estático: es gratuito, multiplataforma, soporta decenas de arquitecturas y su decompilador a C es suficientemente bueno como para usarlo como punto de partida real. En este post lo instalamos, cargamos un crackme simple y lo parcheamos para que acepte cualquier contraseña.

## Instalación

Ghidra requiere Java 17 o superior (JDK, no solo JRE).

```bash
# Debian/Ubuntu
sudo apt install openjdk-21-jdk

# Arch
sudo pacman -S jdk21-openjdk

# macOS
brew install openjdk@21
```

Descarga Ghidra desde [ghidra-sre.org](https://ghidra-sre.org/). No hay instalador: descomprime el zip y ejecuta el script.

```bash
unzip ghidra_11.x.x_PUBLIC.zip
cd ghidra_11.x.x_PUBLIC
./ghidraRun
```

La primera vez que lo abres crea un proyecto vacío. Todo en Ghidra vive dentro de proyectos: un proyecto puede contener múltiples binarios y Ghidra guarda el análisis, los comentarios y los renombres entre sesiones.

## El crackme objetivo

Compila este programa de ejemplo. Es lo más simple posible: compara la entrada con una contraseña hardcodeada.

```c
#include <stdio.h>
#include <string.h>

int check_password(const char *input) {
    return strcmp(input, "s3cr3t0") == 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <contraseña>\n", argv[0]);
        return 1;
    }
    if (check_password(argv[1])) {
        puts("Acceso concedido");
        return 0;
    }
    puts("Contraseña incorrecta");
    return 1;
}
```

```bash
gcc -o crackme crackme.c
strip crackme
```

El `strip` elimina los símbolos: sin él, Ghidra mostraría `check_password` directamente y no habría nada que aprender. Con símbolos eliminados tienes que orientarte por el código.

## Cargar el binario en Ghidra

1. **File → Import File** → selecciona `crackme`.
2. Ghidra detecta automáticamente el formato (ELF 64-bit) y la arquitectura (x86-64).
3. Doble clic sobre el binario en el árbol del proyecto para abrirlo en el **CodeBrowser**.
4. Ghidra pregunta si quieres ejecutar el análisis automático. Di que sí con las opciones por defecto.

El análisis tarda entre segundos y minutos dependiendo del tamaño del binario. Para este crackme es instantáneo.

## Orientarse en la interfaz

La ventana principal del CodeBrowser tiene tres paneles que importan:

| Panel | Función |
|-------|---------|
| **Listing** | Vista de ensamblador. Es la fuente de verdad: cada línea corresponde a bytes reales del binario. |
| **Decompiler** | Vista en pseudo-C generada por Ghidra. Sincronizada con Listing: al hacer clic en una instrucción, el decompilador salta a la función correspondiente. |
| **Symbol Tree** | Árbol de funciones, imports, exports y etiquetas. Punto de entrada habitual para navegar. |

La barra de búsqueda (`G` o *Navigation → Go To*) acepta direcciones, nombres de función y etiquetas.

## Encontrar la función relevante

Sin símbolos no hay `check_password` en el árbol. Hay dos caminos:

**Camino 1: seguir los strings.** La cadena `"Contraseña incorrecta"` tiene que estar en el binario. En Ghidra: *Window → Defined Strings*, busca "incorrecta". Doble clic en el resultado y llegas al string en `.rodata`. Desde ahí, clic derecho → *References → Show References to Address* para ver qué función lo usa. Eso te lleva al `main`.

**Camino 2: buscar `strcmp` en la IAT/PLT.** En el Symbol Tree, expande `Functions` → busca `strcmp`. Si está como import resuelto, clic derecho → *References* → llegas a todos los call sites. Con un crackme simple solo hay uno.

Una vez en `main`, el decompilador muestra algo así:

```c
undefined8 main(int argc, char **argv) {
    int iVar1;

    if (argc < 2) {
        printf("Uso: %s <contraseña>\n", *argv);
        return 1;
    }
    iVar1 = strcmp(argv[1], "s3cr3t0");
    if (iVar1 == 0) {
        puts("Acceso concedido");
        return 0;
    }
    puts("Contraseña incorrecta");
    return 1;
}
```

Ghidra ha inlineado `check_password` porque el compilador la optimizó como inline. Esto es normal: `-O0` las mantiene separadas, `-O1` o superior las puede colapsar. El resultado funcional es el mismo.

## Leer el ensamblador del punto crítico

Haz clic en la llamada a `strcmp` en el decompilador. El panel Listing salta a esa instrucción. Verás algo como:

```nasm
CALL       strcmp
TEST       EAX, EAX
JNZ        LAB_acceso_denegado
```

`strcmp` devuelve 0 si las cadenas son iguales. `TEST EAX, EAX` activa la flag Zero (ZF) si EAX es 0. `JNZ` (Jump if Not Zero) salta al mensaje de error si ZF=0, es decir, si las cadenas *no* son iguales.

Para que el programa siempre conceda acceso necesitas que este salto nunca se tome. Hay dos opciones:

| Modificación | Instrucción original | Instrucción parcheada | Bytes originales | Bytes nuevos |
|---|---|---|---|---|
| Nop el salto | `JNZ rel8` | `NOP; NOP` | `75 XX` | `90 90` |
| Invertir el salto | `JNZ rel8` | `JZ rel8` | `75 XX` | `74 XX` |

La opción más limpia es `NOP; NOP`: elimina el salto completamente y la ejecución cae directamente al bloque de acceso concedido.

## Parchear con Ghidra

Ghidra puede modificar bytes directamente sobre su copia del binario y exportar el resultado.

1. En el panel **Listing**, haz clic sobre la instrucción `JNZ`.
2. *Edit → Patch Instruction* — abre un editor de instrucción en línea. Cambia `JNZ` por `NOP`.
3. La instrucción `JNZ rel8` ocupa 2 bytes, `NOP` solo 1. Ghidra rellena el byte sobrante con otro `NOP` automáticamente.

Alternativamente, puedes editar los bytes directamente:

1. Clic sobre el byte `75` en la columna de bytes del panel Listing.
2. *Edit → Patch Bytes*.
3. Cambia `75 XX` por `90 90`.

Para exportar el binario parcheado:

*File → Export Program* → selecciona formato **Binary (Raw bytes)**. Esto vuelca el binario con los parches aplicados.

```bash
chmod +x crackme_patched
./crackme_patched cualquiercosa
# Acceso concedido
```

## Renombrar funciones y variables

El análisis va a la velocidad que renombras. Cada vez que identificas qué hace una función, nómbrala. En Ghidra: clic sobre el nombre de la función → `L` (Label) → escribe el nombre nuevo.

Lo mismo con variables locales en el decompilador: clic sobre `iVar1` → `L` → `resultado_strcmp`. Ghidra actualiza todos los usos en el decompilador y en el Listing simultáneamente.

Los renombres se guardan en el proyecto, no en el binario. Si cierras y vuelves a abrir el proyecto, todo sigue ahí. Si exportas el binario, los nombres no se exportan (son metadatos del análisis, no van en el ELF).

## Shortcuts esenciales

| Atajo | Acción |
|-------|--------|
| `G` | Ir a dirección o símbolo |
| `L` | Renombrar símbolo bajo el cursor |
| `T` | Añadir tipo a una variable |
| `;` | Añadir comentario de línea |
| `Ctrl+Z` | Deshacer (también deshace parches) |
| `X` | Ver referencias a la dirección actual |
| `F` | Buscar en el Listing |
| `Ctrl+F` | Buscar en el decompilador |

## Puntos frecuentes de confusión

**El decompilador miente a veces.** El pseudo-C es una aproximación. Si el decompilador produce código que no tiene sentido lógico, baja al Listing y lee el ASM directamente. El ASM es siempre la fuente de verdad.

**Ghidra no analiza lo que no conoce.** Si una función usa offsets dinámicos (`call rax`, tabla de funciones), Ghidra puede no resolver el target. En esos casos aparece `(*)` o `undefined` en el decompilador. Se resuelven con análisis manual o con la ejecución del binario en un debugger.

**Parches en Ghidra no modifican el binario en disco.** Hasta que no uses *Export Program*, el binario original no cambia. Ghidra trabaja sobre su propia copia interna.

## Próximo paso

El análisis estático en Ghidra te dice qué hay en el código. El análisis dinámico —ejecutar el binario con un debugger y ver qué pasa instrucción a instrucción— completa el cuadro. El siguiente post cubre [x64dbg para principiantes](/reversing/x64dbg-principiantes/): breakpoints, step into/over y cómo aplicar parches en caliente mientras el programa corre.
