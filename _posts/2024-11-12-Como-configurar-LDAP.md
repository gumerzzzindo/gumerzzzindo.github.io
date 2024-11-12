---
layout: post
title: "Instalación y configuración de LDAP server"
---

LDAP es un protocolo de red que permite gestionar servicios de directorio de una manera centralizada. Los directorios son bases de datos optimizadas para la lectura que almacenan información de forma jerárquica y se utilizan para gestionar y organizar información sobre usuarios, grupos, dispositivos y recursos dentro de una red.

## 1. Intalación

Primero deberemos actualizar los repos con el gestor que tengamos en nuestro caso (apt).

```bash
sudo apt update
sudo apt install slapd ldap-utils -y
```

Una vez instalemos los paquetes de LDAP nos saldrá una pantalla para configurar la contraseña de admin.

**En caso de que no nos pida crear una contraseña deberemos lanzar:**

```bash
sudo dpkg-reconfigure slapd
```

### a. Configuración usando phpldapadmin:

```bash
sudo apt-get install phpldapadmin
```




