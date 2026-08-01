---
layout: single
title: "AFL++: Fuzzing de Binarios en Linux"
date: 2026-08-01
categories: [tutoriales, reversing]
tags: [fuzzing, afl, afl++, vulnerability-research, linux, asan, crash-triage, binary-analysis]
excerpt: "Cómo configurar AFL++ para hacer fuzzing de binarios en Linux: instrumentación en tiempo de compilación, modo QEMU para cerrados, ASAN y triaje de crashes."
permalink: /tutoriales/afl-plus-plus-fuzzing-binarios-linux/
---

AFL++ es el fork más activo de american fuzzy lop. En la práctica es el fuzzer coverage-guided de referencia para binarios en Linux: instrumenta el código en tiempo de compilación, mide el número de bordes (edges) en el grafo de control de flujo que cada entrada activa, y muta las entradas que descubren bordes nuevos. El ciclo se repite hasta que el corpus no crece o el proceso se detiene manualmente.

Este post cubre la configuración desde cero, un target de ejemplo con un bug real inducido, integración con AddressSanitizer y el triaje de los crashes encontrados.

---

## Instalación

Compilar desde fuente siempre da la versión más reciente del compilador y del runtime:

```bash
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make all
sudo make install
```

Comprueba que los wrappers del compilador están disponibles:

```bash
afl-clang-fast --version
afl-clang-fast++ --version
```

AFL++ necesita permisos para ajustar la CPU affinity y el governor. Antes de lanzar cualquier fuzzing:

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

Sin esto AFL++ va a quejarse cada segundo con advertencias de rendimiento.

---

## Target de ejemplo

Escribe un parser mínimo con un heap buffer overflow deliberado:

```c
// target.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t magic;
    uint32_t length;
    uint8_t  data[256];
} record_t;

void parse_record(const uint8_t *buf, size_t len) {
    if (len < 8) return;

    record_t rec;
    uint32_t magic  = *(uint32_t *)buf;
    uint32_t rlen   = *(uint32_t *)(buf + 4);

    if (magic != 0xDEADBEEF) return;

    // Bug: rlen no está acotado antes de copiar
    memcpy(rec.data, buf + 8, rlen);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    uint8_t buf[4096] = {0};
    size_t  n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    parse_record(buf, n);
    return 0;
}
```

El bug está en `memcpy(rec.data, buf + 8, rlen)`: si el campo `rlen` del fichero de entrada supera 256, se produce un heap overflow que ASAN detectará como `heap-buffer-overflow` o `stack-buffer-overflow` dependiendo de dónde estén los structs.

---

## Compilar con instrumentación

```bash
afl-clang-fast -o target target.c
```

El wrapper instrumenta el binario para rastrear edges. Si el proyecto usa autotools o cmake, sobreescribe el compilador mediante variables de entorno:

```bash
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --prefix=/tmp/target-afl
make -j$(nproc)
```

Para proyectos que usan LLVM LTO (link-time optimization), el wrapper `afl-clang-lto` produce una cobertura más precisa:

```bash
CC=afl-clang-lto CXX=afl-clang-lto++ make -j$(nproc)
```

---

## Corpus inicial

AFL++ requiere al menos un input válido que el target sea capaz de procesar sin salir inmediatamente. Lo mínimo:

```bash
mkdir corpus
python3 -c "
import struct
magic  = struct.pack('<I', 0xDEADBEEF)
length = struct.pack('<I', 10)
data   = b'AAAAAA' * 2
open('corpus/seed1', 'wb').write(magic + length + data)
"
```

Un corpus con entradas diversas (distintos tamaños, valores de campos) acelera la exploración. Herramientas como `afl-cmin` reducen un corpus grande al subconjunto mínimo que mantiene la cobertura total.

---

## Ejecutar AFL++

```bash
afl-fuzz -i corpus -o findings -- ./target @@
```

`@@` es el placeholder que AFL++ reemplaza con la ruta del fichero de input en cada ejecución. La pantalla de status muestra:

| Campo | Significado |
|---|---|
| `exec speed` | Ejecuciones por segundo |
| `edges found` | Bordes únicos descubiertos |
| `total crashes` | Crashes únicos (deduplicados por stack trace) |
| `cycles done` | Vueltas completas sobre el corpus |
| `pending favs` | Entradas interesantes pendientes de mutar |

Para paralelizar en todos los cores disponibles:

```bash
# instancia maestra
afl-fuzz -M master -i corpus -o findings -- ./target @@
# instancias secundarias en terminales separadas
afl-fuzz -S slave1 -i corpus -o findings -- ./target @@
afl-fuzz -S slave2 -i corpus -o findings -- ./target @@
```

Las instancias comparten hallazgos vía `findings/` de forma automática.

---

## Modo QEMU para binarios sin código fuente

Cuando el código fuente no está disponible, AFL++ instrumenta el binario en tiempo de ejecución mediante un backend QEMU:

```bash
# requiere que AFL++ se haya compilado con soporte QEMU
make -C AFLplusplus/qemu_mode

afl-fuzz -Q -i corpus -o findings -- ./target_closed @@
```

QEMU mode es entre 2x y 10x más lento que la instrumentación nativa, pero no requiere recompilar. Para binarios con protecciones (ASLR, PIE, stack canaries) funciona igual de bien porque QEMU emula el entorno completo.

---

## Integración con AddressSanitizer

ASAN detecta clases de bugs que un crash ordinario no produce: heap overflows de un byte, use-after-free, reads fuera de bounds que no sigfaultan porque la página está mapeada. Compilar con ASAN expone bugs que AFL++ de otra forma nunca vería como crash:

```bash
AFL_USE_ASAN=1 afl-clang-fast -o target_asan target.c
```

Lanzar una instancia secundaria contra el binario con ASAN mientras la maestra usa el binario sin instrumentación:

```bash
# maestra: binario rápido sin ASAN
afl-fuzz -M master -i corpus -o findings -- ./target @@

# secundaria: binario lento con ASAN, detecta bugs sutiles
afl-fuzz -S asan -i corpus -o findings -- ./target_asan @@
```

ASAN añade overhead de 2x-3x en velocidad de ejecución. Usarlo en todas las instancias mata el throughput.

---

## Persistent mode

Relanzar un proceso por cada input tiene un coste fijo de fork(). Para parsers que no tienen estado global, el persistent mode ejecuta miles de inputs dentro del mismo proceso:

```c
// target_persistent.c
#include "AFL/afl-fuzz.h"
#include <string.h>
#include <stdint.h>

extern void parse_record(const uint8_t *buf, size_t len);

__AFL_FUZZ_INIT();

int main(void) {
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        parse_record(buf, len);
    }

    return 0;
}
```

```bash
afl-clang-fast -o target_pers target_persistent.c
afl-fuzz -i corpus -o findings -- ./target_pers
```

El speedup respecto al modo estándar es típicamente 5x-20x. Condición necesaria: la función que se fuzza no debe tener side effects globales que contaminen ejecuciones posteriores. Si los tiene, hay que limpiarlos manualmente dentro del bucle.

---

## Triaje de crashes

Los crashes van a `findings/master/crashes/`. AFL++ los agrupa por señal y por hash de backtrace, pero el número puede crecer rápido. El flujo de triaje:

```bash
# reproducir un crash específico
./target_asan findings/master/crashes/id:000000,sig:11,...

# minimizar el input que produce el crash
afl-tmin -i findings/master/crashes/id:000000,sig:11,... -o crash_min.bin -- ./target_asan @@

# minimizar el corpus completo conservando cobertura total
afl-cmin -i findings/master/queue/ -o corpus_min -- ./target @@
```

`afl-tmin` produce el input más pequeño que sigue crashando el target. Combinado con el backtrace de ASAN, la lectura del bug se reduce a unos minutos.

---

## Cobertura post-fuzzing

Para saber qué porcentaje del código alcanzó el fuzzing, compilar con `lcov` e importar el corpus:

```bash
afl-clang-fast --coverage -o target_cov target.c
for f in findings/master/queue/id:*; do ./target_cov "$f" 2>/dev/null; done
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory cov_html
```

Un porcentaje de cobertura bajo (< 30%) en un target complejo sugiere que el corpus inicial es pobre o que hay barreras de input (magic bytes, checksums) que AFL++ no está superando. En ese caso la solución es escribir un diccionario de tokens:

```bash
# dic.txt
"magic"="\\xEF\\xBE\\xAD\\xDE"
"rlen_max"="\\x00\\x01\\x00\\x00"
```

```bash
afl-fuzz -x dic.txt -i corpus -o findings -- ./target @@
```

---

## Referencias

- [AFLplusplus — documentación oficial](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)
- Zalewski, M. — *american fuzzy lop technical whitepaper*, 2014
- Heuse, M. — *AFL++ QEMU and Frida mode*, WOOT 2022
- [OSS-Fuzz](https://github.com/google/oss-fuzz) — integración de AFL++ y libFuzzer en proyectos open source
