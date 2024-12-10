# Resumen del análisis del malware: AsyncRAT

---

### Identificadores del archivo
- **Nombre:** AsyncRAT  
- **SHA256:** `f0045c024fc4e796911fa5a1e597c22f011723c8301c4a903dc140699a707621`
- **SHA3-384:** `f1b1f4ec7588322dd4ab1237517b69e32fdc5dfbf23626e64dfc3d2e1625d7beeafb64787b5bcbf86c5867ed426fc32c`
- **SHA1:** `d9607463fcf1ce55eb8e5649b65047ee526d8060`
- **MD5:** `c684a63e08404601807c7bd5af233d28`
- **Humanhash:** `friend-beryllium-asparagus-item`

---

### Comportamiento observado

1. **Ejecución inicial:**
   - El malware se ejecuta desde un directorio temporal:  
     **Ruta:** `C:\Users\admin\AppData\Local\Temp\f0045c024fc4e796911fa5a1e597c22f011723c8301c4a903dc140699a707621.exe`.
   - Es lanzado por un proceso denominado `starbowlines.exe`, ubicado en:  
     **Ruta:** `C:\Users\admin\AppData\Local\anaboly\starbowlines.exe`.

2. **Persistencia:**
   - Escribe un archivo `.vbs` para garantizar su reinicio al iniciar el sistema:  
     **Archivo:** `C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\starbowlines.vbs`.

3. **Conexiones de red:**
   - Realiza múltiples conexiones (50 en total) al servidor de comando y control (C2):  
     **Dirección IP:** `69.174.99.6`  
     **Puerto:** `7000`  
     **Herramienta utilizada:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`.

4. **Interacción con el sistema:**
   - Recopila información del sistema, incluyendo:
     - Nombre del equipo.
     - Distribución de teclado.
     - GUID, una clave en el registro relacionada con la criptografía.
   - Utiliza esta información posiblemente para identificar la máquina y su ubicación.

5. **Técnicas de evasión:**
   - Usa nombres de archivo largos y aleatorios para dificultar la detección.
   - Se ejecuta en directorios ocultos como `Temp` y `AppData`.

---

### Análisis y clasificación
- **Tipo:** RAT (Remote Access Trojan)  
- **Familia:** AsyncRAT  
- **Propósito:**
  - Conexión remota con el servidor C2 para control.
  - Persistencia en el sistema infectado.
  - Posible descarga de payloads adicionales desde el C2.

---

### Recomendaciones
1. **Aislar el equipo infectado:**
   - Desconectar de la red inmediatamente.
   - Revisar otros dispositivos en la misma red para verificar si también están comprometidos.

2. **Eliminar el malware:**
   - Borrar los archivos relacionados (`.exe` y `.vbs`).
   - Revisar el registro para eliminar cualquier clave persistente asociada al malware.

3. **Analizar el tráfico:**
   - Inspeccionar las conexiones a `69.174.99.6` y bloquear la IP en el firewall.

4. **Fortalecer la seguridad:**
   - Implementar herramientas de protección avanzada, como EDR.
   - Capacitar a los usuarios sobre phishing y prácticas seguras.
