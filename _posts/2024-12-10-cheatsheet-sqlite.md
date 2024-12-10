---
layout: post
title: "Instalación y configuración de LDAP server"
---

# SQLite Cheatsheet: Comandos Específicos de SQLite

SQLite incluye comandos exclusivos que no forman parte del estándar SQL, generalmente usados para gestionar la consola interactiva de SQLite. Aquí tienes una guía con los comandos menos comunes:

---

## **SQLite Interactive Commands**

### **1. Ayuda y documentación**
- `.help`: Lista todos los comandos disponibles.
- `.man`: Muestra el manual completo de SQLite (si está disponible).
- `.changes`: Muestra el número de filas afectadas por el último comando SQL.

---

### **2. Inspección de la base de datos**
- `.databases`: Muestra las bases de datos actualmente abiertas.
- `.tables`: Lista todas las tablas en la base de datos.
- `.schema [tabla]`: Muestra el esquema de la base de datos o de una tabla específica.
- `.dump [tabla]`: Exporta el esquema y los datos de una tabla o base completa.
- `.indexes [tabla]`: Lista todos los índices de la base o de una tabla específica.

---

### **3. Configuración y formato**
- `.mode MODE`: Cambia el modo de salida (ej., `csv`, `json`, `column`).
- `.headers on/off`: Activa o desactiva los encabezados de las columnas.
- `.nullvalue VALOR`: Especifica cómo mostrar valores nulos (por defecto: vacío).
- `.separator SEP`: Define el separador para el modo `csv`.

---

### **4. Gestión de transacciones y archivos**
- `.read archivo`: Ejecuta comandos SQL desde un archivo.
- `.save archivo`: Guarda la base de datos en un archivo específico.
- `.open archivo`: Abre una base de datos existente o la crea.
- `.backup archivo`: Crea una copia de seguridad de la base de datos.
- `.restore archivo`: Restaura una base de datos desde una copia de seguridad.

---

### **5. Depuración y rendimiento**
- `.timer on/off`: Activa o desactiva el cronómetro para medir tiempos de ejecución.
- `.explain on/off`: Activa o desactiva la visualización de planes de ejecución SQL.
- `.stats on/off`: Muestra estadísticas sobre el rendimiento del servidor.

---

### **6. Salida y exportación**
- `.output archivo`: Redirige la salida de comandos a un archivo.
- `.once archivo`: Envía la salida del próximo comando a un archivo.
- `.print mensaje`: Imprime un mensaje en la consola.

---

### **7. Salir de la consola interactiva**
- `.quit`: Cierra la consola interactiva de SQLite.
- `.exit`: Alias de `.quit`.

---

### **Ejemplo de Configuración: Exportar a CSV**
```sql
.mode csv
.headers on
.output usuarios.csv
SELECT * FROM usuarios;
.output stdout
