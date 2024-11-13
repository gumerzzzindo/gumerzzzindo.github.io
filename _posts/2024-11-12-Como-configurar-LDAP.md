---
layout: post
title: "Instalación y configuración de LDAP server"
---

LDAP es un protocolo de red que permite gestionar servicios de directorio de una manera centralizada. Los directorios son bases de datos optimizadas para la lectura que almacenan información de forma jerárquica y se utilizan para gestionar y organizar información sobre usuarios, grupos, dispositivos y recursos dentro de una red.

## 1. Instalación

Primero deberemos actualizar los repos con el gestor que tengamos en nuestro caso (apt).

```bash
sudo apt update
sudo apt install slapd ldap-utils -y
```

Una vez instalemos los paquetes de LDAP nos saldrá una pantalla para configurar la contraseña de admin.

**Para configurar de una manera más "grafica" podemos lanzar:**

```bash
sudo dpkg-reconfigure slapd
```

### a. Configuración usando phpldapadmin:

Para instalar phpldapadmin y empezar a configurar el archivo principal.

```bash
sudo apt-get install phpldapadmin
sudo nano /etc/phpldapadmin/config.php
```

### b. Configuración de ldap usando ssl/tls

Antes de generar certificados autofirmados, es recomendable crear una carpeta para organizarlos y facilitar el control de los permisos.

Para hacer ldap con tls debes saber tu nombre de host y deberás agregar una línea en /etc/hosts::

127.0.1.1       ldap-server.juja.corp ldap-server

```bash
cd ~
mkdir ssl-ldap
cd ssl-ldap
```

Ahora podemos empezar con los certificados. **Es necesario usar contraseña**

```bash
openssl genrsa -aes128 -out ldap-server.juja.corp.key 4096
openssl rsa -in ldap-server.juja.corp.key -out ldap-1.juja.corp.key
openssl req -new -days 3650 -key ldap-server.juja.corp.key -out ldap-1.juja.corp.csr
sudo openssl x509 -in ldap-server.juja.corp.csr -out ldap-server.corp.crt -req -signkey ldap-server.juja.corp.key -days 3650
```

Si vamos bien veremos un mensaje **Certificate request self-signature ok**, por lo que deberemos ubicar estos certis en **/etc/ldap/sasl2**:

```bash
sudo cp ldap-server.juja.corp.key /etc/ldap/sasl2
sudo cp ldap-server.juja.corp.crt /etc/ldap/sasl2
sudo cp /etc/ssl/certs/ca-certificates.crt /etc/ldap/sasl2
sudo chown openldap:openldap -R /etc/ldap/sasl2/*
```

Ahora deberemos crear una configuración para decirle al server que funcione por SSL.

```ssl-ldap.ldif
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/sasl2/ca-certificates.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/sasl2/ldap-server.juja.corp.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/sasl2/ldap-server.juja.corp.key
```

Para comprobar la configuración podemos hacer el siguiente comando: **sudo ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=config" "(objectClass=olcGlobal)"**