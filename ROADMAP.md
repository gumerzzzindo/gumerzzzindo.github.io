# Roadmap del blog

Notas internas — no se publica como post. Lista viva de ideas y pequeñas tareas de mantenimiento.

## Prioridad: serie "Reversing para principiantes"

El blog tiene bastante contenido de análisis de malware y CTF, pero faltaba una entrada
real a ingeniería inversa desde cero. Plan de serie progresiva (cada entrada enlaza a la
siguiente):

1. **Assembly x86 para principiantes** — registros, instrucciones básicas, stack, tu
   primer `objdump -d`. *(primer post escrito, ver `_posts/`)*
2. **Anatomía de un binario ELF/PE** — secciones, headers, entry point, comparativa
   ELF vs PE para quien viene de Windows o Linux.
3. **Tu primer crackme con Ghidra** — instalación, navegación básica, parchear un
   `strcmp` para ver el mensaje de "¡correcto!".
4. **x64dbg para principiantes** — breakpoints, step into/over, parches en caliente,
   diferencias con Ghidra (estático vs dinámico).
5. **Calling conventions: cdecl, stdcall, fastcall, x64** — por qué importa al leer
   un desensamblado y cómo identificar cada una a simple vista.
6. **Ofuscación básica: cómo reconocerla** — XOR simple, stack strings, control flow
   flattening ligero. Ejercicios con crackmes.de.
7. **De C a ASM y vuelta** — compilar funciones pequeñas con distintos niveles de
   optimización (`-O0` vs `-O2`) y ver cómo cambia el ensamblador.
8. **Anti-debugging 101** — `IsDebuggerPresent`, timing checks, por qué son triviales
   de saltar y cómo hacerlo.

Encaja bien con lo que ya existe (`syscalls-windows-vs-win32-api`, `wannacry-strings-killswitch`,
`antivirus-internals-amsi-etw-cfg-wdac`, `dirty-frag`) — esta serie le da una base a
quien llega a esos posts sin contexto previo.

## Otras ideas de posts

- **ROP chains 101** — construir una cadena de ROP simple desde cero contra un binario
  con NX activado, sin frameworks (a mano), luego mostrar cómo lo automatiza pwntools.
- **YARA para principiantes** — escribir tus primeras reglas a partir de los strings
  de un binario ya analizado en el blog (ej. el driver PE64 `13ab592c`).
- **Diffing de binarios con BinDiff/diaphora** — comparar dos versiones de un mismo
  binario (parcheado vs sin parchear) para localizar el fix de una CVE.
- **UPX por dentro** — cómo identificar un binario empaquetado con UPX y desempaquetarlo
  a mano sin usar `upx -d`.
- **Introducción a syscalls en Linux (ASM puro)** — escribir un "hola mundo" sin libc,
  usando `syscall` directamente, como contraparte del post de syscalls de Windows.
- **Shellcoding 101** — shellcode mínimo de Linux x86_64, encoding y restricciones
  habituales (sin bytes nulos, etc.).
- **Esteganografía aplicada a malware** — payloads ocultos en imágenes, cómo detectarlos
  con `binwalk`/`zsteg`.
- **Cheat sheet de Ghidra** — atajos de teclado, scripts útiles, decompiler vs disassembly.

## Pequeños arreglos pendientes (mantenimiento)

- [x] Crear página de categoría `/reversing/` — había posts etiquetados con
      `reverse-engineering` (wannacry, dirty-frag, syscalls) pero ninguna landing page
      para la categoría, a diferencia de `/malware/`, `/tutoriales/` y `/writeups/`.
- [ ] Revisar si conviene añadir "Reversing" a la navbar principal (`_data/navigation.yml`)
      una vez la serie tenga 3-4 posts; de momento se mantiene minimal por la decisión
      previa de simplificar el navbar.
- [ ] Auditar imágenes de header: todas usan URLs externas de Wikimedia Commons —
      considerar alojarlas localmente en `assets/images/headers/` para no depender de
      enlaces externos que puedan romperse.
- [ ] El post `2026-06-10-13ab592c51354e97611b4a77859f3ce7.md` usa el hash MD5 como slug;
      mantenerlo así por consistencia con el resto de análisis de malware con nombre real
      desconocido, pero documentar el criterio en `CLAUDE.md` para no dudarlo en el futuro.
- [ ] Revisar longitud de excerpts: algunos posts antiguos (2024) no siguen el límite de
      una línea que sí cumplen los posts de 2026.

## Categorías a considerar a futuro

- `reversing` — ingeniería inversa pura (ya creada la landing page, pendiente de llenar
  con la serie de arriba).
- `pwn` / `exploiting` — si se empieza a escribir sobre explotación binaria más allá de
  EternalBlue.
