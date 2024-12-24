# Informe Técnico de Explotación de la Máquina "Sea" de HTB

**Fecha**: 24 de diciembre de 2024  
**Máquina**: Sea (HTB)

Hoy he conseguido vulnerar la máquina **Sea** de HTB. A continuación, detallo los pasos técnicos que seguí para obtener acceso y escalar privilegios en el sistema.

## Paso 1: Escaneo de puertos

Lo primero que realicé fue un escaneo de puertos a través de `nmap`. Los puertos abiertos encontrados fueron:

- **22/tcp** (SSH)
- **80/tcp** (HTTP)

```bash
nmap -p 22,80 sea.htb
```

## Paso 2: Análisis de la Web

Al visitar la página web en el puerto 80, observé que era un sitio relacionado con bicicletas. El sitio parecía utilizar un CMS, pero no era evidente a simple vista. Sin embargo, al utilizar el modo guiado en HTB, se me indicó que era un CMS.

Al realizar un análisis más detallado mediante fuzzing, logré identificar el nombre del CMS y su versión. El CMS se identificó como WonderCMS.

```bash
gobuster dir -u http://sea.htb -w /usr/share/wordlists/dirb/common.txt

```

## Paso 3: Identificación de Vulnerabilidad

Con el nombre y la versión del CMS, realicé una búsqueda y encontré un CVE relacionado con una vulnerabilidad en WonderCMS:

***CVE-2023-41425***
Este CVE describe una vulnerabilidad de Remote Code Execution (RCE) mediante Cross-Site Scripting (XSS).
## Paso 4: Explotación de la Vulnerabilidad (RCE con XSS)
Para explotar esta vulnerabilidad, utilicé un exploit en Python que alojaba un servidor. Este servidor permitía ejecutar una reverse shell cuando el administrador accedía a una URL específica. La reverse shell se ejecutaba con los privilegios del usuario www-data.

Una vez ejecutado, obtuve acceso al sistema con los permisos de www-data.

Paso 5: Búsqueda de Credenciales
Una vez dentro del sistema, procedí a explorar los directorios del aplicativo hasta encontrar una base de datos del administrador. Dentro de esta base de datos, localicé la contraseña hasheada del administrador.

Para descifrar la contraseña, utilicé herramientas como Hashcat o John the Ripper para realizar un brute force.

bash'''
hashcat -m 0 -a 0 hash.txt /path/to/wordlist
'''
La contraseña recuperada fue mychemicalromance.

Paso 6: Conexión SSH
Con la contraseña descifrada, me conecté al sistema vía SSH como el usuario amay.

```bash
ssh amay@sea.htb
```

## Paso 7: Investigación de Privilegios Locales

Una vez dentro como amay, mi primer objetivo fue buscar capabilities o utilizar herramientas como LinPEAS para encontrar posibles escaladas de privilegios. Sin embargo, siguiendo el modo guiado de HTB, descubrí que había un servicio corriendo en el puerto 8080, accesible solo desde localhost.

Para pivotar a este servicio, utilicé SSH Tunneling para redirigir el tráfico desde mi máquina local.

```bash
ssh amay@sea.htb -L 8080:127.0.0.1:8080
```

## Paso 8: Acceso al Servicio Local

Una vez redirigido el tráfico, accedí al servicio en localhost:8080. El servicio requería un usuario y contraseña para acceder. Usando las credenciales de amay, logré ingresar y me di cuenta de que el servicio era similar a Webmin.

## Paso 9: Escalamiento de Privilegios

Para escalar privilegios, utilicé Burp Suite para interceptar la solicitud y modificarla. Inyecté el siguiente comando para añadir permisos de sudo al usuario amay sin requerir una contraseña.

```bash
/etc/passwd+%26%26+echo+"amay+ALL=(ALL)+NOPASSWD:+ALL"+>+/etc/sudoers.d/amay+#
```

Este comando modificó el archivo sudoers y permitió al usuario amay ejecutar cualquier comando como root sin tener que ingresar una contraseña.

## Paso 10: Conclusión
Con este escalamiento de privilegios, obtuve acceso completo al sistema como root. Este ejercicio demuestra cómo una vulnerabilidad RCE en un CMS puede ser explotada para ganar acceso inicial, y cómo técnicas como SSH Tunneling y la modificación de sudoers pueden ser utilizadas para escalar privilegios de forma efectiva.