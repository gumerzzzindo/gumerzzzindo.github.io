---
layout: single
title: "WannaCry — Extracción de Strings y el Kill Switch"
date: 2026-06-15
categories: [malware, analisis]
tags: [wannacry, ransomware, strings, kill-switch, static-analysis, floss, pe, reverse-engineering]
excerpt: "Análisis estático de WannaCry: cómo extraer strings de un PE, qué encontramos y por qué una URL hardcodeada detuvo el mayor ransomware de la historia"
permalink: /analisis/wannacry-strings-killswitch/
---

En mayo de 2017, WannaCry infectó más de 230.000 sistemas en 150 países en cuestión de horas. Lo paró un investigador de seguridad por 10,69 dólares — el coste de registrar un dominio que encontró en las strings del binario.

Este post cubre el análisis estático básico: cómo extraer strings de un PE, qué revelan en el caso de WannaCry, y qué hace exactamente el kill switch a nivel de código.

---

## La muestra

El dropper principal de WannaCry (el launcher que contiene el ransomware embebido):

```
SHA256: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
MD5:    db349b97c37d22f5ea1d1841e3c89eb4
Nombre: mssecsvc.exe / tasksche.exe
Tipo:   PE32 executable (GUI) Intel 80386
```

Puedes obtenerla en [MalwareBazaar](https://bazaar.abuse.ch) o VirusTotal. Trabaja siempre en una VM aislada sin acceso a red real, o en REMnux/FlareVM con networking desactivado.

---

## Paso 1: Triage inicial

Antes de strings, confirma qué tienes delante:

```bash
file wannacry.exe
# PE32 executable (GUI) Intel 80386, for MS Windows

die wannacry.exe   # Detect-It-Easy
# PE32, Compiler: Microsoft Visual C/C++(2010)[EXE32]
# Packer: -
```

No está empaquetado, lo que hace la extracción de strings directa y útil. Con un packer (UPX, MPRESS, custom) las strings estarían cifradas en el payload y `strings` devolvería basura del stub.

Comprueba el entropy por sección:

```bash
python3 -c "
import pefile, math, collections
pe = pefile.PE('wannacry.exe')
for s in pe.sections:
    data = s.get_data()
    freq = collections.Counter(data)
    entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values() if c)
    print(f'{s.Name.decode().strip(chr(0)):<12} entropy={entropy:.2f}')
"
```

```
.text        entropy=6.21
.rdata       entropy=4.87
.data        entropy=3.94
.rsrc        entropy=7.99
```

La sección `.rsrc` con entropy ~8.0 es llamativa — ahí está el payload cifrado (el ransomware real, `tasksche.exe`) embebido como recurso.

---

## Paso 2: Extracción de strings con `strings`

La herramienta más básica. Filtra secuencias de bytes imprimibles de longitud mínima:

```bash
strings -n 8 wannacry.exe
strings -n 8 -e l wannacry.exe   # wide strings (UTF-16LE, habitual en Windows)
```

Del output de strings interesantes (filtrado del ruido):

```
# Wide strings (-e l):
www.iuqerfsodp9ifjaposdfjhposdfjhpOIJBOIJFDSOIJWEFJHSFD.com
mssecsvc2.0
Microsoft Security Center (2.0) Service
C:\%s\qeriuwjhrf
tasksche.exe
WNcry@2ol7
C:\Windows\tasksche.exe
icacls . /grant Everyone:F /T /C /Q
attrib +h .
cmd.exe /c "%s"

# ASCII strings:
.wnry
WANACRY!
WanaDecryptor
hiberfil.sys
bootsect.bak
```

En menos de un minuto ya tienes el dominio del kill switch, el nombre del servicio instalado (`mssecsvc2.0`), la extensión que añade el ransomware (`.wnry`), y el magic byte `WANACRY!` del formato de ficheros cifrados.

---

## Paso 3: FLOSS para strings ofuscadas

`strings` solo ve strings literales en el binario. Si el malware construye strings en runtime (XOR, stack strings, concatenación) no aparecen. FLOSS (Mandiant FLARE Obfuscated String Solver) emula la ejecución para extraerlas:

```bash
floss wannacry.exe
```

En el caso de WannaCry, FLOSS confirma las mismas strings más algunas construidas en stack, incluyendo rutas temporales y nombres de mutex. No hay gran ofuscación aquí — el autor priorizó velocidad de desarrollo sobre evasión.

Para malware más sofisticado (Emotet, Cobalt Strike stagers) FLOSS marca la diferencia.

---

## El kill switch — qué hace exactamente

El código del dropper, antes de hacer nada destructivo, ejecuta esto (pseudocódigo del desensamblado):

```c
HINTERNET hInternet = InternetOpenA(
    "Mozilla/5.0",
    INTERNET_OPEN_TYPE_DIRECT,
    NULL, NULL, 0
);

HINTERNET hUrl = InternetOpenUrlA(
    hInternet,
    "http://www.iuqerfsodp9ifjaposdfjhposdfjhpOIJBOIJFDSOIJWEFJHSFD.com",
    NULL, 0,
    INTERNET_FLAG_RELOAD,
    0
);

if (hUrl != NULL) {
    // El dominio resolvió y respondió → salir
    ExitProcess(0);
}

// El dominio no existe → continuar con la infección
install_service();
extract_and_run_ransomware();
```

Si la petición HTTP tiene éxito (el dominio existe y responde), el malware termina inmediatamente. Si falla (NXDOMAIN o timeout), continúa con la infección.

### Por qué está ahí: anti-sandbox

La hipótesis más aceptada es que es una técnica anti-sandbox. Muchos sandboxes de análisis automático (Cuckoo, Any.run en configuraciones antiguas) responden a **cualquier** petición DNS con una IP válida para capturar tráfico de red. Si el malware detecta que el dominio "inexistente" resuelve, asume que está siendo analizado y se detiene.

El autor nunca esperó que nadie registrara ese dominio en el mundo real.

### El registro del dominio

Marcus Hutchins (MalwareTech) estaba analizando la muestra en vivo el 12 de mayo de 2017. Vio la comprobación del dominio en el tráfico de red, comprobó que no estaba registrado, lo registró por 10,69 dólares y lo apuntó a un sinkhole.

En el momento en que el DNS empezó a resolver, todos los sistemas infectados que aún no habían cifrado los ficheros pararon. Los que ya habían comenzado el cifrado no se detuvieron — el check solo ocurre al inicio.

---

## Paso 4: Strings adicionales de interés

Más allá del kill switch, las strings revelan el comportamiento completo:

| String | Significado |
|---|---|
| `mssecsvc2.0` | Nombre del servicio Windows instalado para persistencia |
| `WNcry@2ol7` | Contraseña del ZIP que protege el payload en `.rsrc` |
| `icacls . /grant Everyone:F /T /C /Q` | Permisos totales sobre directorio de trabajo |
| `@Please_Read_Me@.txt` | Nombre de la nota de rescate |
| `00000000.eky`, `00000000.pky` | Ficheros con claves RSA generadas por víctima |
| `taskdl.exe`, `taskse.exe` | Componentes auxiliares embebidos |

La contraseña del ZIP (`WNcry@2ol7`) es especialmente útil: puedes extraer el payload cifrado del recurso y descomprimirlo sin ejecutar nada:

```bash
# Extraer recurso con binwalk o Resource Hacker
binwalk -e wannacry.exe

# El payload suele estar como recurso tipo "XIA" o similar
# Una vez extraído:
unzip -P WNcry@2ol7 payload.zip -d payload/
```

Dentro encontrarás `tasksche.exe` (el cifrador real), los ejecutables auxiliares y los ficheros de configuración del rescate.

---

## Resumen del flujo de análisis

```
wannacry.exe
    │
    ├─ file / DIE          → PE32, sin packer, MSVC 2010
    ├─ entropy por sección → .rsrc alta (payload embebido)
    ├─ strings -n 8        → kill switch URL, service name, extensiones
    ├─ floss               → confirma + stack strings
    └─ extracción .rsrc    → payload ZIP (contraseña: WNcry@2ol7)
```

El análisis estático de un PE sin packer en menos de 15 minutos ya te da: el mecanismo de kill switch, el método de persistencia, la contraseña del payload embebido y las extensiones objetivo. Todo antes de ejecutar una sola instrucción.

---

## Referencias

- [MalwareTech — How to Accidentally Stop a Global Cyber Attack](https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html)
- [FLOSS — Mandiant FLARE](https://github.com/mandiant/flare-floss)
- [MalwareBazaar — WannaCry samples](https://bazaar.abuse.ch/browse/tag/WannaCry/)
- [Análisis técnico Microsoft](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/)
