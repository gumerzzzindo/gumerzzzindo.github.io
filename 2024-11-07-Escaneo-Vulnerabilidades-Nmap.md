---
layout: post
title: "Escaneo y Explotación de Vulnerabilidades con Nmap"
---

Para buscar vulnerabilidades (CVE) utilizando Nmap, puedes aprovechar su motor de scripts (NSE - Nmap Scripting Engine). Nmap incluye una variedad de scripts que pueden detectar vulnerabilidades conocidas. Aquí te explico cómo usarlos y cómo proceder una vez que encuentres una CVE.

## 1. Scripts de Nmap para identificar CVEs

Nmap incluye una serie de scripts que te ayudarán a identificar posibles vulnerabilidades, muchos de los cuales están orientados a la detección de versiones vulnerables de software.

### a. Script de detección de versiones

El script más básico para identificar posibles CVEs es el siguiente:

```bash
nmap -sV --script vuln <IP>
```

Este comando:
- `-sV`: Detecta versiones de los servicios en ejecución.
- `--script vuln`: Ejecuta el script `vuln`, que busca vulnerabilidades conocidas en los servicios detectados.

### b. Scripts específicos de vulnerabilidades

Puedes usar scripts específicos que buscan vulnerabilidades en ciertos servicios. Algunos de los más útiles son:

- **smb-vuln** (para vulnerabilidades de SMB/CIFS como EternalBlue):

  ```bash
  nmap -p 445 --script smb-vuln* <IP>
  ```

- **http-vuln-** (para vulnerabilidades HTTP conocidas):

  ```bash
  nmap -p 80,443 --script http-vuln-* <IP>
  ```

- **ssl-enum-ciphers** (para detectar vulnerabilidades SSL):

  ```bash
  nmap --script ssl-enum-ciphers -p 443 <IP>
  ```

### c. Uso de NSE para escanear CVEs concretas

Si conoces el servicio que está corriendo, pero quieres comprobar si está afectado por vulnerabilidades específicas, puedes usar scripts dedicados a CVEs específicas. Aquí hay algunos ejemplos:

- Detectar **Heartbleed** (CVE-2014-0160) en servicios SSL/TLS:

  ```bash
  nmap -p 443 --script ssl-heartbleed <IP>
  ```

- Detectar vulnerabilidades HTTP específicas (como **Shellshock** - CVE-2014-6271):

  ```bash
  nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi <IP>
  ```

## 2. Automatización de escaneos de vulnerabilidades

Para realizar un escaneo más profundo que cubra múltiples servicios y CVEs:

```bash
nmap --script vuln --script-args=unsafe=1 <IP>
```

Esto ejecutará todos los scripts disponibles que buscan vulnerabilidades conocidas, algunos de los cuales pueden ser más invasivos.

## 3. Una vez identificada la CVE: ¿Cómo buscar un exploit?

Una vez que has identificado un CVE, el siguiente paso es encontrar un exploit que puedas usar para atacar la vulnerabilidad.

### a. Buscar en Exploit Databases

Pasos para encontrar exploits:

- **Exploit-DB** (Base de datos de exploits más popular):
  - Ir a: [https://www.exploit-db.com](https://www.exploit-db.com)
  - Introducir el CVE que encontraste en la barra de búsqueda, por ejemplo, `CVE-2021-34527`.

  Exploit-DB mostrará cualquier exploit relacionado con ese CVE, junto con descripciones y el código de exploit que puedes descargar.

- **Searchsploit** (Herramienta de línea de comandos para buscar exploits localmente): Si tienes exploit-db instalado en tu máquina, puedes usar searchsploit para buscar exploits offline directamente en tu terminal.

  ```bash
  sudo apt install exploitdb
  searchsploit CVE-2021-34527
  ```

- **NVD** (National Vulnerability Database): También puedes buscar detalles sobre la vulnerabilidad en el sitio de NVD: [https://nvd.nist.gov](https://nvd.nist.gov)

  Busca el CVE para obtener más detalles, junto con posibles soluciones o mitigaciones.

### b. Buscar en GitHub

A veces, los exploits más recientes o versiones alternativas de exploits pueden estar disponibles en GitHub. Simplemente busca el CVE:

```bash
CVE-XXXX-YYYY exploit site:github.com
```

### c. Metasploit Framework

Metasploit es otra herramienta poderosa que contiene una gran cantidad de exploits para CVEs conocidas. Puedes usar el siguiente flujo para buscar exploits en Metasploit:

- Iniciar Metasploit:

  ```bash
  msfconsole
  ```

- Buscar un exploit:

  ```bash
  search CVE-2021-34527
  ```

  Si Metasploit contiene un exploit para esa vulnerabilidad, puedes configurarlo y ejecutarlo directamente.

## 4. Resumen del flujo de trabajo

1. Escaneo inicial de vulnerabilidades con Nmap:

   ```bash
   nmap -sV --script vuln <IP>
   ```

2. Si detectas una vulnerabilidad con un CVE, busca el exploit:

   - Usando Exploit-DB o Searchsploit para buscar el CVE:

     ```bash
     searchsploit CVE-XXXX-YYYY
     ```

3. Si encuentras un exploit, ejecútalo (usando Metasploit, Python, Bash, etc.).

Con estos pasos puedes automatizar el proceso de identificación de vulnerabilidades y encontrar un exploit específico para comprometer el sistema.
