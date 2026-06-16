---
layout: single
title: "RoguePlanet — Race condition en Windows Defender para escalar a SYSTEM"
date: 2026-06-16
categories: [malware, analisis]
tags: [windows-defender, lpe, race-condition, toctou, privesc, windows, ntfs-junction, vhd, zero-day]
excerpt: "RoguePlanet es un PoC publicado el 10 de junio de 2026 que explota una race condition TOCTOU en el motor de escaneo en tiempo real de Windows Defender para obtener una shell SYSTEM en Windows 10 y Windows 11 completamente parcheados."
permalink: /analisis/rogueplanet-windows-defender-race-condition/
header:
  image: "https://upload.wikimedia.org/wikipedia/commons/thumb/a/a4/20231028_21_49_36-SmartScreen.png/1920px-20231028_21_49_36-SmartScreen.png"
  caption: "Windows SmartScreen — Wikimedia Commons"

---

El 10 de junio de 2026, el mismo día del Patch Tuesday más grande en la historia de Microsoft (~200 vulnerabilidades), el investigador conocido como **Nightmare Eclipse** (también rastreado como Chaotic Eclipse o Dead Eclipse) publicó **RoguePlanet**: un PoC de escalada de privilegios local (LPE) que explota una race condition en Windows Defender y devuelve una shell `NT AUTHORITY\SYSTEM`.

Sin CVE asignado. Sin parche. Confirmado funcionando en máquinas totalmente parcheadas con la actualización acumulativa de junio 2026 (**KB5094126**).

---

## Contexto: el sexto exploit de la serie

RoguePlanet no es un caso aislado. Nightmare Eclipse lleva publicando zero-days contra componentes Windows desde abril de 2026. La cronología:

| Exploit | CVE | Estado |
|---------|-----|--------|
| BlueHammer | CVE-2026-33825 (CVSS 7.8) | Parcheado abril 2026, explotado in-the-wild |
| RedSun | CVE-2026-41091 | Parcheado, explotado in-the-wild |
| UnDefend | CVE-2026-45498 | Parcheado |
| YellowKey | CVE-2026-50507 | Parcheado junio 2026 (Patch Tuesday) |
| GreenPlasma | CVE-2026-45586 | Parcheado junio 2026 (Patch Tuesday) |
| **RoguePlanet** | Sin CVE | **Sin parche** |

El patrón es deliberado: Microsoft parchea los exploits anteriores en Patch Tuesday, el investigador confirma los parches y publica uno nuevo el mismo día. Tres de los anteriores fueron explotados in-the-wild antes de que existiera parche.

---

## La clase del bug: TOCTOU

RoguePlanet abusa de una vulnerabilidad **Time-of-Check to Time-of-Use (TOCTOU)** en el motor de escaneo en tiempo real de Windows Defender.

TOCTOU es una clase de race condition que aparece cuando un programa comprueba una condición (el check) y luego actúa en base a esa comprobación (el use), pero entre ambas operaciones hay una ventana de tiempo en la que el estado puede cambiar. Si un atacante puede modificar ese estado en la ventana correcta, puede hacer que el programa actúe sobre datos distintos a los que comprobó.

En este caso:

1. Defender examina una ruta de fichero con privilegios SYSTEM.
2. Entre la validación de la ruta y la operación de escritura posterior, existe una ventana.
3. El atacante inserta un **NTFS junction point** que redirige esa ruta a una ubicación controlada por él.
4. Defender ejecuta la operación de escritura sobre la ruta ya redirigida, con sus propios privilegios SYSTEM.
5. El código del atacante se ejecuta como SYSTEM.

Esto no es nuevo conceptualmente: BlueHammer (CVE-2026-33825) usó exactamente la misma estrategia — junction points para redirigir escrituras privilegiadas de Defender hacia `C:\Windows\System32`. RoguePlanet demuestra que el hardening aplicado tras BlueHammer fue insuficiente.

---

## Vector de ataque: montaje de disco virtual

El vector de entrega utiliza ficheros **VHD/VHDX** (discos virtuales). El flujo completo desde la perspectiva del atacante:

```
[atacante] crea VHD/VHDX malicioso
     │
     ▼
[entrega] phishing, share de red, descarga directa
     │
     ▼
[víctima] monta el fichero (doble clic en Windows)
     │
     ▼
[Defender] escanea el contenido montado en tiempo real
     │
     ▼
[race window] entre check de ruta y write de Defender
     │
     ▼
[atacante] inserta NTFS junction point durante la ventana
     │
     ▼
[Defender] escribe con SYSTEM en ubicación controlada
     │
     ▼
[resultado] shell SYSTEM
```

El requisito de acceso local significa que RoguePlanet no es un vector de entrada inicial — es una herramienta de post-compromise para pasar de usuario sin privilegios a control total del sistema.

La cadena realista: phishing o robo de credenciales para acceso inicial → RoguePlanet para LPE → movimiento lateral con privilegios SYSTEM.

---

## Fiabilidad del exploit

La naturaleza de las race conditions hace que el éxito no esté garantizado en cada ejecución. El propio investigador indica haber conseguido un **100% de éxito en algunas máquinas**, mientras que en otras el exploit es inconsistente.

ThreatLocker lo reprodujo de forma independiente y confirmó que funciona en Windows 11 completamente parcheado con KB5094126. SecurityWeek también lo verificó.

La variabilidad depende de factores como la carga del sistema, el comportamiento del scheduler, y la velocidad relativa de los threads en competición. No es trivial pero tampoco hace el exploit inutilizable — las race conditions se pueden ejecutar en bucle hasta tener éxito.

---

## Versiones afectadas

| Sistema | Estado |
|---------|--------|
| Windows 10 (con parche junio 2026) | Vulnerable, PoC funciona |
| Windows 11 canal estable (KB5094126) | Vulnerable, PoC funciona |
| Windows 11 Canary | Vulnerable, PoC funciona |
| Windows Server (todas las versiones) | Vulnerable en teoría |

**Windows Server**: el PoC actual **no funciona** en Server porque los usuarios estándar no pueden montar ficheros de disco virtual. Esto es una limitación del PoC, no de la vulnerabilidad subyacente. El investigador confirma que todos los Windows Server son vulnerables y que es posible rediseñar el exploit para superar esta restricción.

---

## Impacto post-explotación

Una explotación exitosa devuelve un `cmd.exe` corriendo como `NT AUTHORITY\SYSTEM`. Desde ahí:

```
- Instalar/ejecutar software arbitrario
- Leer/modificar/borrar cualquier fichero del sistema
- Crear nuevas cuentas locales con privilegios
- Deshabilitar Defender u otro endpoint protection
- Volcar credenciales de LSASS
- Movimiento lateral usando la máquina como pivot
```

Es privilegio total sobre la máquina local.

---

## Mitigación

No existe parche. Microsoft tiene conocimiento del problema y se espera un fix OOB o en el Patch Tuesday de julio 2026. Mientras tanto:

**1. Restringir el montaje de VHD/VHDX para usuarios estándar (Group Policy)**

Elimina el vector de entrega del PoC actual:

```
Configuración del equipo → Plantillas administrativas →
Sistema → Acceso de almacenamiento extraíble →

"Todos los accesos de almacenamiento extraíble: Denegar todo acceso"
```

O vía registro:

```powershell
# Bloquear montaje de discos virtuales para usuarios sin privilegios
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v DenyDeviceIDs /t REG_DWORD /d 1 /f
```

La forma más directa es usar una GPO que restrinja `StorageDevicePolicies` o aplicar controles sobre la asociación de ficheros `.vhd` y `.vhdx`.

**2. Activar reglas ASR (Attack Surface Reduction)**

Las reglas ASR no parchean la race condition pero añaden fricción a los pasos de post-explotación más comunes:

```powershell
# Bloquear robo de credenciales desde LSASS
Set-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0 -AttackSurfaceReductionRules_Actions Enabled

# Bloquear abuso de drivers vulnerables firmados
Set-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
```

**3. Verificar que Defender corre en modo activo**

En modo pasivo, los componentes de Defender siguen activos pero el número de operaciones que pueden ser redirigidas varía. Confirmar el modo en todos los endpoints:

```powershell
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled
```

**4. Monitorizar MSRC**

Vigilar la página de [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability) para el advisory y el parche OOB.

---

## Referencias

- [GitHub — MSNightmare/RoguePlanet](https://github.com/MSNightmare/RoguePlanet)
- [CyberSecurityNews — New Windows Defender 0-Day Exploit "RoguePlanet"](https://cybersecuritynews.com/windows-defender-0-day-exploit-rogueplanet/)
- [CybelAngel — Microsoft Defender RoguePlanet Zero-Day: 7 Things to Know](https://cybelangel.com/blog/rogueplanet-microsoft-defender-zero-day-2026/)
- [BleepingComputer — Microsoft Defender RoguePlanet zero-day grants SYSTEM privileges](https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/)
